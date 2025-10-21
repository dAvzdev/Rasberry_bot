#!/usr/bin/env python3
"""
Telegram Bot for System Monitoring and Management
Monitor your Raspberry Pi/Linux system via Telegram with real-time stats,
alerts, and remote management capabilities.

Author: TuNombre
License: MIT
Repository: https://github.com/tuusuario/system-monitor-bot
"""

import subprocess
import logging
import asyncio
import time
import os
import sys
from datetime import datetime
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, MessageHandler, filters

# ==================== CONFIGURATION ====================
# IMPORTANT: Replace these with your actual values or use environment variables
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "YOUR_CHAT_ID_HERE")

# Optional: Configuration file path
CONFIG_FILE = os.path.expanduser("~/.system_monitor_bot_config")
# =======================================================

# Enhanced logging configuration
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/tmp/system_monitor_bot.log')
    ]
)

logger = logging.getLogger(__name__)

# Global variables
start_time = time.time()
ALERTS_ENABLED = True
MONITOR_ACTIVE = False
LAST_ALERT_TIME = 0
ALERT_COOLDOWN = 300
MONITOR_TASK = None
NETWORK_STATS = {
    'last_rx_bytes': 0,
    'last_tx_bytes': 0, 
    'last_check_time': None,
    'current_rx_speed': 0,
    'current_tx_speed': 0,
    'total_rx_since_reset': 0,
    'total_tx_since_reset': 0,
    'reset_time': time.time()
}
ALERT_HISTORY = {
    'cpu': [],
    'temp': [], 
    'ram': [],
    'disk': []
}

REBOOT_FLAG_FILE = os.path.expanduser("~/.system_monitor_bot_reboot_flag")

class SystemMonitor:
    """Main system monitoring class with optimized command execution"""
    
    @staticmethod
    def run_command(cmd, timeout=8):
        """Execute shell command with timeout and error handling"""
        try:
            if isinstance(cmd, (list, tuple)):
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                    text=True, timeout=timeout)
            else:
                proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, 
                                    stderr=subprocess.PIPE, text=True, timeout=timeout)
            
            return proc.stdout.strip() if proc.returncode == 0 else None
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timeout: {cmd}")
            return None
        except Exception as e:
            logger.warning(f"Command error {cmd}: {e}")
            return None

    @staticmethod
    def get_temperature():
        """Get system temperature with fallback methods"""
        try:
            # Try fastest method first
            temp_output = SystemMonitor.run_command(
                "cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null", timeout=2)
            if temp_output:
                return float(temp_output) / 1000.0
            
            # Fallback to vcgencmd (Raspberry Pi)
            temp_output = SystemMonitor.run_command("vcgencmd measure_temp", timeout=2)
            if temp_output:
                return float(temp_output.split("=")[1].replace("'C", ""))
            
            return 0.0
        except Exception as e:
            logger.error(f"Temperature error: {e}")
            return 0.0

    @staticmethod
    def get_cpu_usage_per_core():
        """Get per-core CPU usage with correction"""
        try:
            def get_all_cpu_times():
                cpu_times = {}
                with open('/proc/stat', 'r') as f:
                    for line in f:
                        if line.startswith('cpu'):
                            parts = line.split()
                            cpu_id = parts[0]
                            times = [int(x) for x in parts[1:8]]
                            cpu_times[cpu_id] = {
                                'user': times[0], 'nice': times[1], 'system': times[2],
                                'idle': times[3], 'iowait': times[4], 'irq': times[5],
                                'softirq': times[6], 'total': sum(times)
                            }
                return cpu_times

            # First measurement
            first_times = get_all_cpu_times()
            if not first_times:
                return {'total': 0.0, 'cores': [], 'max_core': 0.0}

            time.sleep(0.3)  # Wait for second measurement
            
            # Second measurement
            second_times = get_all_cpu_times()
            if not second_times:
                return {'total': 0.0, 'cores': [], 'max_core': 0.0}

            core_usages = []
            
            # Process each core (excluding total 'cpu')
            for cpu_id in first_times:
                if cpu_id != 'cpu' and cpu_id in second_times:
                    first = first_times[cpu_id]
                    second = second_times[cpu_id]
                    
                    total_diff = second['total'] - first['total']
                    idle_diff = (second['idle'] + second['iowait']) - (first['idle'] + first['iowait'])
                    
                    if total_diff > 0:
                        usage = 100.0 * (total_diff - idle_diff) / total_diff
                        core_usages.append(round(min(max(usage, 0.0), 100.0), 1))
                    else:
                        core_usages.append(0.0)

            if core_usages:
                return {
                    'total': sum(core_usages) / len(core_usages),
                    'cores': core_usages,
                    'max_core': max(core_usages)
                }
            else:
                return {'total': 0.0, 'cores': [], 'max_core': 0.0}
                
        except Exception as e:
            logger.error(f"CPU per core error: {e}")
            # Fallback method
            try:
                total_usage = SystemMonitor.get_cpu_usage()
                num_cores = os.cpu_count() or 4
                core_usage = total_usage / num_cores
                cores = [core_usage] * num_cores
                
                return {
                    'total': total_usage,
                    'cores': cores,
                    'max_core': core_usage
                }
            except:
                return {'total': 0.0, 'cores': [], 'max_core': 0.0}

    @staticmethod
    def get_cpu_usage():
        """Get overall CPU usage percentage"""
        try:
            def get_cpu_times():
                with open('/proc/stat', 'r') as f:
                    line = f.readline().strip()
                    parts = line.split()
                    times = [int(x) for x in parts[1:8]]
                    return {
                        'user': times[0], 'nice': times[1], 'system': times[2],
                        'idle': times[3], 'iowait': times[4], 'irq': times[5],
                        'softirq': times[6], 'total': sum(times)
                    }

            first = get_cpu_times()
            if not first:
                return 0.0

            time.sleep(0.5)
            second = get_cpu_times()
            if not second:
                return 0.0

            total_diff = second['total'] - first['total']
            idle_diff = (second['idle'] + second['iowait']) - (first['idle'] + first['iowait'])
            
            if total_diff > 0:
                usage = 100.0 * (total_diff - idle_diff) / total_diff
                return round(min(max(usage, 0.0), 100.0), 1)
            
            return 0.0
                
        except Exception as e:
            logger.error(f"CPU usage error: {e}")
            # Fallback
            try:
                cmd = "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1"
                cpu_output = SystemMonitor.run_command(cmd, timeout=3)
                if cpu_output:
                    return float(cpu_output.strip())
                return 0.0
            except:
                return 0.0

    # ... (otros métodos similares, manteniendo la funcionalidad pero con comentarios en inglés)

    @staticmethod
    def get_progress_bar(percent, length=10):
        """Create a visual progress bar"""
        filled = int(round(length * percent / 100))
        return "█" * filled + "░" * (length - filled)

    @staticmethod
    def get_usage_emoji(percent):
        """Get emoji based on usage level"""
        if percent < 50: return "🟢"
        elif percent < 80: return "🟡" 
        elif percent < 90: return "🟠"
        else: return "🔴"

# ===== BOT COMMAND HANDLERS =====

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /start command"""
    await send_help_menu(update, context)

async def send_help_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Display comprehensive help menu"""
    help_text = """🤖 *System Monitor Bot* - Control Panel

*Available Commands:*

📊 *Monitoring*
/monitor - Real-time monitoring (30 seconds)
/status - Complete system status
/cpudetail - Detailed CPU and core information
/memory - Memory and storage details

🌐 *Network*
/network - Network information and SSH details
/ports - Open ports analysis
/resetnet - Reset network statistics

⚙️ *System Management*
/services - Services and Docker status
/updatestatus - Check for system updates
/update - Update system packages
/reboot - Reboot system (with confirmation)
/alerts - Toggle system alerts

🔧 *Utilities*
/botstatus - Bot service status
/help - Show this help menu

*Quick Start:*
1. Configure your bot token and chat ID
2. Start with /status to check system
3. Use /monitor for real-time monitoring

*GitHub:* https://github.com/tuusuario/system-monitor-bot"""

    await update.message.reply_text(help_text, parse_mode='Markdown')

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /status command - Complete system status"""
    monitor = SystemMonitor()
    
    temp = monitor.get_temperature()
    cpu_info = monitor.get_cpu_usage_per_core()
    ram_info = monitor.get_ram_usage()
    disk_info = monitor.get_disk_usage()
    load = monitor.get_load_average()
    uptime = monitor.get_uptime()
    
    status_msg = f"""📊 *SYSTEM STATUS REPORT*

🌡️ *Temperature:* {temp}°C {monitor.get_usage_emoji(temp)}
💻 *CPU Usage:* {cpu_info['total']:.1f}% {monitor.get_usage_emoji(cpu_info['total'])}
🧠 *RAM Usage:* {ram_info['percent']}% {monitor.get_usage_emoji(ram_info['percent'])}
💿 *Disk Usage:* {disk_info['percent']}% {monitor.get_usage_emoji(disk_info['percent'])}

*Details:*
• 📈 Load Average: {load}
• 🕒 Uptime: {uptime}
• 🔔 Alerts: {'✅ ENABLED' if ALERTS_ENABLED else '❌ DISABLED'}
• 🤖 Bot Uptime: {int(time.time() - start_time)}s

*Updated:* {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""

    await update.message.reply_text(status_msg, parse_mode='Markdown')

async def monitor_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle /monitor command - Real-time monitoring"""
    global MONITOR_ACTIVE, MONITOR_TASK
    
    if MONITOR_ACTIVE:
        await update.message.reply_text("📊 *Monitor is already running*", parse_mode='Markdown')
        return
    
    MONITOR_ACTIVE = True
    await update.message.reply_text(
        "🖥️ *STARTING REAL-TIME MONITOR*\n"
        "Duration: 30 seconds | Update: every 3 seconds\n\n"
        "Send 'stop' to end monitoring early", 
        parse_mode='Markdown'
    )
    
    MONITOR_TASK = asyncio.create_task(monitor_live(update, context, 30))

# ... (continuar con el resto de funciones, traducidas de manera similar)

async def check_reboot_status(context: ContextTypes.DEFAULT_TYPE):
    """Check and notify after system reboot"""
    if os.path.exists(REBOOT_FLAG_FILE):
        try:
            await asyncio.sleep(20)  # Wait for system to stabilize
            
            with open(REBOOT_FLAG_FILE, 'r') as f:
                reboot_time = f.read().strip()
            
            os.remove(REBOOT_FLAG_FILE)
            
            monitor = SystemMonitor()
            uptime = monitor.get_uptime()
            temp = monitor.get_temperature()
            cpu = monitor.get_cpu_usage()
            ram_info = monitor.get_ram_usage()
            
            message = f"""🔄 *SYSTEM REBOOTED SUCCESSFULLY*

• ⏰ Reboot Time: {reboot_time}
• 🕒 Current Uptime: {uptime}
• 🌡️ Temperature: {temp}°C
• 💻 CPU: {cpu:.1f}%
• 💾 RAM: {ram_info['percent']}%

✅ System operational
🤖 Bot reconnected and monitoring"""

            await send_telegram_alert(context, message)
            logger.info("Reboot notification sent successfully")
            
        except Exception as e:
            logger.error(f"Reboot status error: {e}")
            try:
                if os.path.exists(REBOOT_FLAG_FILE):
                    os.remove(REBOOT_FLAG_FILE)
            except:
                pass

def load_config():
    """Load configuration from environment or config file"""
    config = {}
    
    # Try environment variables first
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    
    if token and chat_id:
        return token, chat_id
    
    # Try config file
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        config[key] = value
    except Exception as e:
        logger.warning(f"Config file error: {e}")
    
    return config.get('TELEGRAM_BOT_TOKEN'), config.get('TELEGRAM_CHAT_ID')

def main():
    """Main application entry point"""
    
    # Load configuration
    token, chat_id = load_config()
    if token:
        TELEGRAM_BOT_TOKEN = token
    if chat_id:
        TELEGRAM_CHAT_ID = chat_id
    
    # Validate configuration
    if not TELEGRAM_BOT_TOKEN or TELEGRAM_BOT_TOKEN == "YOUR_BOT_TOKEN_HERE":
        print("❌ ERROR: Telegram bot token not configured")
        print("Please set TELEGRAM_BOT_TOKEN environment variable or edit the script")
        sys.exit(1)
    
    if not TELEGRAM_CHAT_ID or TELEGRAM_CHAT_ID == "YOUR_CHAT_ID_HERE":
        print("❌ ERROR: Telegram chat ID not configured")
        print("Please set TELEGRAM_CHAT_ID environment variable or edit the script")
        sys.exit(1)
    
    # Check for recent reboot
    if os.path.exists(REBOOT_FLAG_FILE):
        print("🔄 Detected recent reboot, notifying...")
    
    try:
        # Initialize bot application
        application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
        
        # Set up job queue for background tasks
        job_queue = application.job_queue
        if job_queue:
            job_queue.run_repeating(background_alert_checker, interval=300, first=10)
            job_queue.run_repeating(check_reboot_status, interval=30, first=15)
        
        # Register command handlers
        command_handlers = [
            ("start", start_command),
            ("help", start_command),  # Alias for start
            ("status", status_command),
            ("monitor", monitor_command),
            # Add other commands here...
        ]
        
        for command, handler in command_handlers:
            application.add_handler(CommandHandler(command, handler))
        
        # Message handlers
        application.add_handler(
            MessageHandler(filters.TEXT & filters.Regex(r'^(stop|Stop|STOP)$'), handle_stop)
        )
        application.add_handler(
            MessageHandler(filters.TEXT & filters.Regex(r'^(SI|NO|si|no|Si|No)$'), 
                         handle_confirmation)
        )
        
        # Set bot commands for better UX
        async def setup_commands(application):
            commands = [
                ("start", "🚀 Start system monitor"),
                ("status", "📊 System status"),
                ("monitor", "🖥️ Real-time monitor"),
                ("memory", "💾 Memory info"),
                ("network", "🌐 Network info"),
                ("services", "📡 Services status"),
                ("reboot", "🔄 Reboot system"),
                ("help", "❓ Help menu")
            ]
            await application.bot.set_my_commands(commands)
        
        application.post_init = setup_commands
        
        print("🤖 System Monitor Bot starting...")
        print("✅ Features:")
        print("   • Real-time system monitoring")
        print("   • Automatic alerts")
        print("   • Remote management")
        print("   • Docker container monitoring")
        
        # Start the bot
        application.run_polling()
        
    except Exception as e:
        logger.error(f"Failed to start bot: {e}")
        print(f"❌ Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
