#!/usr/bin/env python3

"""
Telegram Bot for System Monitoring and Management
Monitor Raspberry Pi/Linux systems with real-time stats and remote management from Telegram_bot.

Author: David Valadés
Repository: https://github.com/dAvzdev/system-monitor-bot
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

# Improved logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/tmp/telegram_bot.log')
    ]
)

# === CONFIGURATION ===
TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID_HERE"
# =====================

# Simple and correct verification
if not TELEGRAM_BOT_TOKEN:
    print("❌ ERROR: Token not configured")
    sys.exit(1)

print(f"✅ Token correctly configured: {TELEGRAM_BOT_TOKEN[:10]}...")

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

REBOOT_FLAG_FILE = os.path.expanduser("~/.telegram_bot_reboot_flag")


class SystemMonitor:
    
    @staticmethod
    def run_command(cmd, timeout=8):
        """Execute a shell command optimized"""
        try:
            if isinstance(cmd, (list, tuple)):
                proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            else:
                proc = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            
            return proc.stdout.strip() if proc.returncode == 0 else None
        except subprocess.TimeoutExpired:
            logging.warning(f"Timeout in command: {cmd}")
            return None
        except Exception as e:
            logging.warning(f"Error in command {cmd}: {e}")
            return None

    @staticmethod
    def get_temperature():
        """Get optimized temperature"""
        try:
            # Try faster method first
            temp_output = SystemMonitor.run_command("cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null", timeout=2)
            if temp_output:
                return float(temp_output) / 1000.0
            
            # Fallback to vcgencmd
            temp_output = SystemMonitor.run_command("vcgencmd measure_temp", timeout=2)
            if temp_output:
                return float(temp_output.split("=")[1].replace("'C", ""))
            
            return 0.0
        except Exception as e:
            logging.error(f"Error in get_temperature: {e}")
            return 0.0

    @staticmethod
    def get_cpu_usage_per_core():
        """Get usage per individual core - CORRECTED VERSION"""
        try:
            # Direct method using /proc/stat for each core
            def get_all_cpu_times():
                cpu_times = {}
                with open('/proc/stat', 'r') as f:
                    for line in f:
                        if line.startswith('cpu'):
                            parts = line.split()
                            cpu_id = parts[0]
                            times = [int(x) for x in parts[1:8]]
                            cpu_times[cpu_id] = {
                                'user': times[0],
                                'nice': times[1],
                                'system': times[2], 
                                'idle': times[3],
                                'iowait': times[4],
                                'irq': times[5],
                                'softirq': times[6],
                                'total': sum(times)
                            }
                return cpu_times

            # First measurement
            first_times = get_all_cpu_times()
            if not first_times:
                return {'total': 0.0, 'cores': [], 'max_core': 0.0}

            # Wait for second measurement
            time.sleep(0.3)
            
            # Second measurement
            second_times = get_all_cpu_times()
            if not second_times:
                return {'total': 0.0, 'cores': [], 'max_core': 0.0}

            core_usages = []
            
            # Process each core (excluding the total 'cpu')
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
            logging.error(f"Error in get_cpu_usage_per_core: {e}")
            # Fallback: use general method divided by cores
            try:
                total_usage = SystemMonitor.get_cpu_usage()
                # Estimate per core usage (distribute total)
                num_cores = 4  # Assuming 4 cores
                core_usage = total_usage / num_cores
                cores = [core_usage] * num_cores
                
                return {
                    'total': total_usage,
                    'cores': cores,
                    'max_core': core_usage
                }
            except:
                return {'total': 0.0, 'cores': [0.0, 0.0, 0.0, 0.0], 'max_core': 0.0}

    @staticmethod
    def get_cpu_usage():
        try:
            def get_cpu_times():
                with open('/proc/stat', 'r') as f:
                    line = f.readline().strip()
                    parts = line.split()
                    times = [int(x) for x in parts[1:8]]  # user, nice, system, idle, iowait, irq, softirq
                    return {
                        'user': times[0],
                        'nice': times[1],
                        'system': times[2],
                        'idle': times[3],
                        'iowait': times[4],
                        'irq': times[5],
                        'softirq': times[6],
                        'total': sum(times)
                    }

            # First measurement
            first = get_cpu_times()
            if not first:
                return 0.0

            # Wait for second measurement
            time.sleep(0.5)
            
            # Second measurement
            second = get_cpu_times()
            if not second:
                return 0.0

            # Calculate differences
            total_diff = second['total'] - first['total']
            idle_diff = (second['idle'] + second['iowait']) - (first['idle'] + first['iowait'])
            
            if total_diff > 0:
                usage = 100.0 * (total_diff - idle_diff) / total_diff
                return round(min(max(usage, 0.0), 100.0), 1)
            
            return 0.0
                
        except Exception as e:
            logging.error(f"Error in get_cpu_usage: {e}")
            # Fallback to fast method
            try:
                cmd = "top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1"
                cpu_output = SystemMonitor.run_command(cmd, timeout=3)
                if cpu_output:
                    return float(cpu_output.strip())
                return 0.0
            except:
                return 0.0

    @staticmethod
    def get_network_usage():
        """Get complete network information - CORRECTED"""
        try:
            interface = SystemMonitor.run_command("ip route | awk '/default/ {print $5; exit}'") or 'eth0'
            ip_local = SystemMonitor.run_command("hostname -I | awk '{print $1}'")
            public_ip = SystemMonitor.run_command("curl -s ifconfig.me") or "Not available"
            
            # Get speed using existing method
            rx_speed, tx_speed, total_rx_reset, total_tx_reset = SystemMonitor.get_network_speed(interface)
            
            return {
                'interface': interface,
                'ip_local': ip_local or 'N/A',
                'public_ip': public_ip,
                'rx_speed': rx_speed,
                'tx_speed': tx_speed,
                'total_rx_reset': total_rx_reset,
                'total_tx_reset': total_tx_reset
            }
        except Exception as e:
            logging.error(f"Error in get_network_usage: {e}")
            return {
                'interface': 'N/A', 
                'ip_local': 'N/A', 
                'public_ip': 'N/A',
                'rx_speed': 0.0,
                'tx_speed': 0.0,
                'total_rx_reset': 0,
                'total_tx_since_reset': 0
            }

    @staticmethod
    def get_top_processes():
        """Get top 5 processes by CPU and RAM usage"""
        try:
            # Simplified and more robust command
            cpu_cmd = "ps -eo comm,pcpu --sort=-pcpu --no-headers | head -5"
            cpu_output = SystemMonitor.run_command(cpu_cmd)
            cpu_processes = []
            
            if cpu_output:
                for line in cpu_output.split('\n'):
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            name = parts[0]
                            usage = parts[-1]
                            clean_name = SystemMonitor.clean_process_name(name)
                            cpu_processes.append((clean_name, float(usage)))
            
            ram_cmd = "ps -eo comm,pmem --sort=-pmem --no-headers | head -5"
            ram_output = SystemMonitor.run_command(ram_cmd)
            ram_processes = []
            
            if ram_output:
                for line in ram_output.split('\n'):
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            name = parts[0]
                            usage = parts[-1]
                            clean_name = SystemMonitor.clean_process_name(name)
                            ram_processes.append((clean_name, float(usage)))
            
            return {'cpu': cpu_processes, 'ram': ram_processes}
        except Exception as e:
            logging.error(f"Error in get_top_processes: {e}")
            return {'cpu': [], 'ram': []}

    @staticmethod 
    def clean_process_name(name):
        if not name:
            return "unknown"
        
        if '/' in name:
            name = name.split('/')[-1]
        
        if ' ' in name:
            name = name.split(' ')[0]
        
        name = name.replace('.py', '').replace('.sh', '').replace('.bin', '').replace('./', '').strip()
        
        return name[:12] + "..." if len(name) > 12 else name or "process"

    @staticmethod
    def get_ram_usage(): # Detailed RAM usage
        try:
            cmd = "free -h | awk '/^Mem:/{print $2 \" \" $3 \" \" $4 \" \" $7}'"
            ram_output = SystemMonitor.run_command(cmd)
            
            if ram_output:
                total, used, free, available = ram_output.split()
                
                # Percentage calculation
                cmd_percent = "free | awk '/^Mem:/{printf \"%.0f\", $3/$2 * 100}'"
                percent_output = SystemMonitor.run_command(cmd_percent)
                percent = int(percent_output) if percent_output else 0
                
                return {
                    'percent': percent,
                    'used': used,
                    'free': free,
                    'available': available,
                    'total': total
                }
            return {'percent': 0, 'used': '0G', 'free': '0G', 'available': '0G', 'total': '0G'}
        except Exception as e:
            logging.error(f"Error in get_ram_usage: {e}")
            return {'percent': 0, 'used': 'N/A', 'free': 'N/A', 'available': 'N/A', 'total': 'N/A'}

    @staticmethod
    def get_disk_usage(): # Detailed HDD usage
        try:
            cmd = "df -h / | awk 'NR==2{print $2 \" \" $3 \" \" $4 \" \" $5}'"
            disk_output = SystemMonitor.run_command(cmd)
            
            if disk_output:
                total, used, free, percent = disk_output.split()
                return {
                    'percent': int(percent.replace('%', '')),
                    'used': used,
                    'free': free,
                    'total': total
                }
            return {'percent': 0, 'used': '0G', 'free': '0G', 'total': '0G'}
        except Exception as e:
            logging.error(f"Error in get_disk_usage: {e}")
            return {'percent': 0, 'used': 'N/A', 'free': 'N/A', 'total': 'N/A'}

    @staticmethod
    def get_network_speed(interface): # eth speed
        global NETWORK_STATS
        
        try:
            # Get current bytes
            rx_bytes = SystemMonitor.run_command(f"cat /sys/class/net/{interface}/statistics/rx_bytes 2>/dev/null") or "0"
            tx_bytes = SystemMonitor.run_command(f"cat /sys/class/net/{interface}/statistics/tx_bytes 2>/dev/null") or "0"
            
            current_rx = int(rx_bytes)
            current_tx = int(tx_bytes)
            current_time = time.time()
            
            # If first time, initialize
            if NETWORK_STATS['last_check_time'] is None:
                NETWORK_STATS['last_rx_bytes'] = current_rx
                NETWORK_STATS['last_tx_bytes'] = current_tx
                NETWORK_STATS['last_check_time'] = current_time
                NETWORK_STATS['total_rx_since_reset'] = 0
                NETWORK_STATS['total_tx_since_reset'] = 0
                return 0.0, 0.0, 0, 0
            
            # Calculate time difference
            time_diff = current_time - NETWORK_STATS['last_check_time']
            if time_diff < 0.1:
                return (NETWORK_STATS['current_rx_speed'], 
                    NETWORK_STATS['current_tx_speed'],
                    NETWORK_STATS['total_rx_since_reset'],
                    NETWORK_STATS['total_tx_since_reset'])
            
            # Calculate speed (bytes per second)
            rx_speed = (current_rx - NETWORK_STATS['last_rx_bytes']) / time_diff
            tx_speed = (current_tx - NETWORK_STATS['last_tx_bytes']) / time_diff
            
            # Convert to MB/s
            rx_speed_mb = rx_speed / (1024 * 1024)
            tx_speed_mb = tx_speed / (1024 * 1024)
            
            # Update accumulated totals since reset
            NETWORK_STATS['total_rx_since_reset'] += (current_rx - NETWORK_STATS['last_rx_bytes'])
            NETWORK_STATS['total_tx_since_reset'] += (current_tx - NETWORK_STATS['last_tx_bytes'])
            
            # Update statistics
            NETWORK_STATS['last_rx_bytes'] = current_rx
            NETWORK_STATS['last_tx_bytes'] = current_tx
            NETWORK_STATS['last_check_time'] = current_time
            NETWORK_STATS['current_rx_speed'] = rx_speed_mb
            NETWORK_STATS['current_tx_speed'] = tx_speed_mb
            
            return (rx_speed_mb, tx_speed_mb,
                    NETWORK_STATS['total_rx_since_reset'], 
                    NETWORK_STATS['total_tx_since_reset'])
            
        except Exception as e:
            logging.error(f"Error in get_network_speed: {e}")
            return 0.0, 0.0, 0, 0

    @staticmethod
    def get_firewall_status(): # Firewall status
        try:
            # Try with UFW
            ufw_status = SystemMonitor.run_command("sudo ufw status 2>/dev/null | head -1")
            if ufw_status and "active" in ufw_status.lower():
                return "✅ UFW Activated"
            
            # Try iptables
            iptables_rules = SystemMonitor.run_command("sudo iptables -L 2>/dev/null | wc -l")
            if iptables_rules and int(iptables_rules) > 8:
                return "🔧 iptables Configured"
            
            # Check for custom rules
            custom_rules = SystemMonitor.run_command("sudo iptables -L 2>/dev/null | grep -v Chain | grep -v target | grep -v '^$' | wc -l")
            if custom_rules and int(custom_rules) > 0:
                return "🔧 Custom Rules"
                
            return "❌ Firewall Disabled"
        except Exception as e:
            logging.error(f"Error in get_firewall_status: {e}")
            return "❓ Unknown Status"

    @staticmethod
    def get_network_services():
        """Get detailed service and port information"""
        try:
            # Detected SSH ports (without duplicates)
            ssh_ports = set()
            ssh_output = SystemMonitor.run_command("ss -tlnp | grep sshd | awk '{print $4}'")
            if ssh_output:
                for line in ssh_output.split('\n'):
                    if ':' in line:
                        port = line.split(':')[-1]
                        ssh_ports.add(port)
            
            # Here change and try to find a way to search 
            common_ports = {
                '22': 'SSH',
                '80': 'HTTP',
                '443': 'HTTPS', 
                '21': 'FTP',
                '25': 'SMTP',
                '53': 'DNS',
                '993': 'IMAPS',
                '995': 'POP3S',
                '3306': 'MySQL',
                '5432': 'PostgreSQL',
                '6379': 'Redis',
                '8080': 'HTTP-Alt',
                '8443': 'HTTPS-Alt'
            }
            
            # Detect active services (without duplicates)
            active_services = set()
            ports_output = SystemMonitor.run_command("ss -tuln | grep LISTEN")
            if ports_output:
                for line in ports_output.split('\n'):
                    for port, service in common_ports.items():
                        if f':{port}' in line:
                            active_services.add(f"{service} (port {port})")
                            break
            
            return {
                'ssh_ports': list(ssh_ports) if ssh_ports else ['22'],
                'active_services': list(active_services),
                'total_listening': len(ports_output.split('\n')) if ports_output else 0
            }
        except Exception as e:
            logging.error(f"Error in get_network_services: {e}")
            return {'ssh_ports': ['22'], 'active_services': [], 'total_listening': 0}

    @staticmethod # Fan state
    def get_fan_state():
        try:
            fan_state = SystemMonitor.run_command("cat /sys/class/thermal/cooling_device0/cur_state 2>/dev/null") or "0"
            states = {
                "0": "💨 Off (0/4)",
                "1": "💨 Low (1/4)", 
                "2": "💨 Medium (2/4)",
                "3": "💨 High (3/4)",
                "4": "💨 Maximum (4/4)"
            }
            return states.get(fan_state.strip(), "💨 Unknown")
        except Exception as e:
            logging.error(f"Error in get_fan_state: {e}")
            return "💨 N/A"

    @staticmethod # Load Avg
    def get_load_average():
        try:
            load_output = SystemMonitor.run_command("cat /proc/loadavg")
            return ' '.join(load_output.split()[:3]) if load_output else "N/A"
        except Exception as e:
            logging.error(f"Error in get_load_average: {e}")
            return "N/A"

    @staticmethod # Uptime
    def get_uptime():
        try:
            uptime_output = SystemMonitor.run_command("cat /proc/uptime")
            if uptime_output:
                seconds = float(uptime_output.split()[0])
                days = int(seconds // 86400)
                hours = int((seconds % 86400) // 3600)
                minutes = int((seconds % 3600) // 60)
                
                if days > 0:
                    return f"{days}d {hours}h {minutes}m"
                elif hours > 0:
                    return f"{hours}h {minutes}m"
                else:
                    return f"{minutes}m"
            return "N/A"
        except Exception as e:
            logging.error(f"Error in get_uptime: {e}")
            return "N/A"

    @staticmethod # Service status
    def get_services_status():
        services = {
            'ssh': 'SSH',
            'nginx': 'Nginx', 
            'mysql': 'MySQL',
            'docker': 'Docker',
            'cron': 'Cron',
        }
        
        status_text = "📡 *SERVICES STATUS:*\n"
        active_count = 0
        
        for service, name in services.items():
            try:
                result = SystemMonitor.run_command(f"systemctl is-active {service}")
                if result == "active":
                    status_text += f"✅ {name}: Active\n"
                    active_count += 1
                else:
                    status_text += f"❌ {name}: Inactive\n"
            except:
                status_text += f"❓ {name}: Error\n"
        
        # Docker info
        docker_info = SystemMonitor.get_docker_containers()
        status_text += f"\n{docker_info}"
        
        return status_text

    @staticmethod # Container status
    def get_docker_containers():
        try:
            # Check Docker
            if not SystemMonitor.run_command("which docker"):
                return "🐋 Docker: Not installed"
            
            if SystemMonitor.run_command("systemctl is-active docker") != "active":
                return "🐋 Docker: Service inactive"
            
            # Get containers
            containers = SystemMonitor.run_command("docker ps -a --format '{{.Names}}|||{{.Status}}'")
            if not containers:
                return "🐋 Docker: No containers"
            
            docker_info = "🐋 *DOCKER CONTAINERS:*\n"
            container_count = 0
            active_count = 0
            
            for line in containers.split('\n'):
                if '|||' in line:
                    container_count += 1
                    name, status = line.split('|||', 1)
                    
                    if "Up" in status:
                        active_count += 1
                        uptime = status.split("Up ")[1].split(")")[0] + ")" if "Up" in status else "Active"
                        docker_info += f"✅ {name}: {uptime}\n"
                    elif "Exited" in status:
                        docker_info += f"❌ {name}: Stopped\n"
                    else:
                        docker_info += f"⚪ {name}: {status}\n"
            
            return f"🐋 Docker: {active_count}/{container_count} active\n\n" + docker_info
            
        except Exception as e:
            logging.error(f"Error in get_docker_containers: {e}")
            return f"🐋 Docker: Error - {str(e)}"

    @staticmethod # Progress bar
    def get_progress_bar(percent, length=10):
        filled = int(round(length * percent / 100))
        return "█" * filled + "░" * (length - filled)

    @staticmethod # Indicator with emojis
    def get_usage_emoji(percent):
        """Returns emoji based on usage level"""
        if percent < 50: return "🟢"
        elif percent < 80: return "🟡" 
        elif percent < 90: return "🟠"
        else: return "🔴"

# ===== CONFIRMATION FUNCTIONS =====

async def handle_confirmation(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles confirmations for reboot and update"""
    user_response = update.message.text.upper()
    
    if context.user_data.get('waiting_reboot_confirmation'):
        if user_response == 'SI':
            context.user_data['waiting_reboot_confirmation'] = False
            await execute_system_reboot(update, context)
        elif user_response == 'NO':
            context.user_data['waiting_reboot_confirmation'] = False
            await update.message.reply_text("✅ *Reboot cancelled*", parse_mode='Markdown')
    
    elif context.user_data.get('waiting_update_confirmation'):
        if user_response == 'SI':
            context.user_data['waiting_update_confirmation'] = False
            await execute_system_update(update, context)
        elif user_response == 'NO':
            context.user_data['waiting_update_confirmation'] = False
            await update.message.reply_text("✅ *Update cancelled*", parse_mode='Markdown')

async def handle_stop(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Stops the monitor"""
    global MONITOR_ACTIVE, MONITOR_TASK
    if MONITOR_ACTIVE and MONITOR_TASK:
        MONITOR_ACTIVE = False
        MONITOR_TASK.cancel()
        await update.message.reply_text("⏹️ *Monitor stopped*", parse_mode='Markdown')

# ===== SYSTEM FUNCTIONS =====

async def check_reboot_status(context: ContextTypes.DEFAULT_TYPE): # Check after reboot with 20" delay
    if os.path.exists(REBOOT_FLAG_FILE):
        try:
            await asyncio.sleep(20)
            
            with open(REBOOT_FLAG_FILE, 'r') as f:
                reboot_time = f.read().strip()
            
            os.remove(REBOOT_FLAG_FILE)
            
            monitor = SystemMonitor()
            uptime = monitor.get_uptime()
            temp = monitor.get_temperature()
            cpu = monitor.get_cpu_usage()
            ram_info = monitor.get_ram_usage()
            
            message = f"""🔄 *SYSTEM REBOOTED SUCCESSFULLY*

• ⏰ *Reboot time:* {reboot_time}
• 🕒 *Uptime:* {uptime}
• 🌡️ *Temperature:* {temp}°C
• 💻 *CPU:* {cpu:.1f}%
• 💾 *RAM:* {ram_info['percent']}%

✅ *Operating system correctly*
🤖 *Bot reconnected and working*"""

            max_attempts = 5  # Increased attempts
            for attempt in range(max_attempts):
                try:
                    await send_telegram_alert(context, message)
                    logging.info("✅ Reboot notification sent successfully")
                    break
                except Exception as e:
                    logging.warning(f"⚠️ Attempt {attempt + 1} failed: {e}")
                    if attempt < max_attempts - 1:
                        await asyncio.sleep(15)  # Increased sleep between attempts
                    else:
                        logging.error("❌ Could not send reboot notification after 5 attempts")
            
        except Exception as e:
            logging.error(f"Error in check_reboot_status: {e}")
            try:
                if os.path.exists(REBOOT_FLAG_FILE):
                    os.remove(REBOOT_FLAG_FILE)
            except:
                pass

async def send_telegram_alert(context: ContextTypes.DEFAULT_TYPE, message: str): # Alert messages
    try:
        await context.bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message, parse_mode='Markdown')
    except Exception as e:
        logging.error(f"Error sending message: {e}")

async def background_alert_checker(context: ContextTypes.DEFAULT_TYPE):
    # Background job
    global LAST_ALERT_TIME, ALERT_HISTORY
    
    if not ALERTS_ENABLED:
        return
    
    current_time = time.time()
    if current_time - LAST_ALERT_TIME < ALERT_COOLDOWN:
        return
    
    try:
        monitor = SystemMonitor()
        temp = monitor.get_temperature()
        cpu = monitor.get_cpu_usage()
        ram_info = monitor.get_ram_usage()
        disk_info = monitor.get_disk_usage()
        
        # Keep history of last 3 measurements
        ALERT_HISTORY['cpu'].append(cpu)
        ALERT_HISTORY['temp'].append(temp)
        ALERT_HISTORY['ram'].append(ram_info['percent'])
        ALERT_HISTORY['disk'].append(disk_info['percent'])
        
        # Keep only last 3 measurements
        for key in ALERT_HISTORY:
            ALERT_HISTORY[key] = ALERT_HISTORY[key][-3:]
        
        alerts = []
        critical_alerts = []
        
        # Check with more intelligent logic
        cpu_avg = sum(ALERT_HISTORY['cpu']) / len(ALERT_HISTORY['cpu'])
        temp_avg = sum(ALERT_HISTORY['temp']) / len(ALERT_HISTORY['temp'])
        
        # Temperature alerts
        if temp > 75:
            critical_alerts.append(f"🚨 *CRITICAL TEMPERATURE ALERT*: {temp}°C")
        elif temp > 70 and temp_avg > 68:
            alerts.append(f"🌡️ *TEMPERATURE ALERT*: {temp}°C")
        
        # CPU alerts
        if cpu > 95:
            critical_alerts.append(f"🚨 *CRITICAL CPU ALERT*: {cpu:.1f}%")
        elif cpu > 85 and cpu_avg > 70:
            alerts.append(f"💻 *CPU ALERT*: {cpu:.1f}%")
        
        # RAM alerts
        if ram_info['percent'] > 95:
            critical_alerts.append(f"🚨 *CRITICAL RAM ALERT*: {ram_info['percent']}%")
        elif ram_info['percent'] > 85:
            alerts.append(f"💾 *RAM ALERT*: {ram_info['percent']}%")
        
        # Disk alerts
        if disk_info['percent'] > 95:
            critical_alerts.append(f"🚨 *FULL DISK ALERT*: {disk_info['percent']}%")
        elif disk_info['percent'] > 85:
            alerts.append(f"💿 *ALMOST FULL ALERT*: {disk_info['percent']}%")
        
        # Send alerts
        if critical_alerts:
            alert_message = "🚨 *CRITICAL SYSTEM ALERTS*\n\n" + "\n".join(critical_alerts)
            alert_message += f"\n\n*⏰ Time:* {datetime.now().strftime('%H:%M:%S')}"
            await send_telegram_alert(context, alert_message)
            LAST_ALERT_TIME = current_time
            logging.info(f"🚨 Critical alerts sent: {critical_alerts}")
            
        elif alerts and (current_time - LAST_ALERT_TIME >= ALERT_COOLDOWN):
            alert_message = "⚠️ *SYSTEM ALERTS*\n\n" + "\n".join(alerts)
            alert_message += f"\n\n*⏰ Time:* {datetime.now().strftime('%H:%M:%S')}"
            await send_telegram_alert(context, alert_message)
            LAST_ALERT_TIME = current_time
            logging.info(f"⚠️ Normal alerts sent: {alerts}")
            
    except Exception as e:
        logging.error(f"❌ Error in background_alert_checker: {e}")

async def execute_system_reboot(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Executes system reboot safely"""
    try:
        flag_dir = os.path.dirname(REBOOT_FLAG_FILE)
        if flag_dir and not os.path.exists(flag_dir):
            os.makedirs(flag_dir, exist_ok=True)
        
        reboot_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(REBOOT_FLAG_FILE, 'w') as f:
            f.write(reboot_time)
        
        os.chmod(REBOOT_FLAG_FILE, 0o644)
        
        await update.message.reply_text(
            "🔄 *REBOOTING SYSTEM...*\n\n"
            "• 📝 Saving configuration...\n"
            "• 🔄 Closing services...\n"
            "• ⏰ Rebooting...\n\n"
            "*You will receive a notification when the system is operational.*",
            parse_mode='Markdown'
        )
        
        await asyncio.sleep(2)
        SystemMonitor.run_command("sudo reboot", timeout=5)
        
    except Exception as e:
        logging.error(f"Error in reboot: {e}")
        try:
            if os.path.exists(REBOOT_FLAG_FILE):
                os.remove(REBOOT_FLAG_FILE)
        except:
            pass
        
        await update.message.reply_text(
            f"❌ *Reboot error:* {str(e)}\n\nExecute manually: `sudo reboot`",
            parse_mode='Markdown'
        )

async def execute_system_update(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Executes system update"""
    progress_message = await update.message.reply_text("🔄 *STARTING SYSTEM UPDATE...*", parse_mode='Markdown')
    
    try:
        await progress_message.edit_text("📦 *UPDATING PACKAGE LIST...*\n\n`apt update` in progress...")
        update_result = SystemMonitor.run_command("sudo apt update", timeout=180)
        
        if not update_result:
            await progress_message.edit_text("❌ *ERROR IN LIST UPDATE*", parse_mode='Markdown')
            return
        
        await progress_message.edit_text("🔍 *CHECKING AVAILABLE UPDATES...*")
        upgradable_cmd = "apt list --upgradable 2>/dev/null | grep -c upgradable"
        upgradable_result = SystemMonitor.run_command(upgradable_cmd)
        upgradable_count = int(upgradable_result) if upgradable_result else 0
        
        if upgradable_count == 0:
            await progress_message.edit_text("✅ *SYSTEM UPDATED*\n\nNo updates available.", parse_mode='Markdown')
            return
        
        await progress_message.edit_text(f"⬆️ *UPDATING {upgradable_count} PACKAGES...*\n\nThis may take several minutes...")
        upgrade_result = SystemMonitor.run_command("sudo apt-get upgrade -y", timeout=1200)
        
        if not upgrade_result:
            await progress_message.edit_text("❌ *ERROR IN PACKAGE UPDATE*", parse_mode='Markdown')
            return
        
        await progress_message.edit_text("🗑️ *CLEANING UNNECESSARY PACKAGES...*")
        SystemMonitor.run_command("sudo apt autoremove -y", timeout=180)
        SystemMonitor.run_command("sudo apt autoclean", timeout=120)
        
        remaining_updates = SystemMonitor.run_command(upgradable_cmd)
        remaining_count = int(remaining_updates) if remaining_updates else 0
        
        if remaining_count > 0:
            success_message = f"""⚠️ *PARTIALLY COMPLETED UPDATE*

*Summary:*
• 📦 Package list updated
• ⬆️ {upgradable_count - remaining_count} of {upgradable_count} packages updated
• 🗑️ System cleaned
• ❌ {remaining_count} pending updates

*Recommendation:*
Run `/reboot` and then `/update` again"""
        else:
            success_message = f"""✅ *UPDATE COMPLETED SUCCESSFULLY*

*Summary:*
• 📦 Package list updated
• ⬆️ {upgradable_count} packages updated
• 🗑️ System cleaned and optimized
• 🎯 System completely updated

*Recommendation:*
If the kernel was updated, run `/reboot` to apply changes"""

        await progress_message.edit_text(success_message, parse_mode='Markdown')
        
    except subprocess.TimeoutExpired:
        await progress_message.edit_text("⏰ *TIME OUT*\n\nThe update took too long. Check status manually.", parse_mode='Markdown')
    except Exception as e:
        logging.error(f"Error in update: {e}")
        await progress_message.edit_text(f"❌ *ERROR DURING UPDATE*\n\n{str(e)}", parse_mode='Markdown')

async def command_botstatus(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Checks the status of the bot and service"""
    try:
        service_status = SystemMonitor.run_command("systemctl is-active telegram-bot.service")
        
        if service_status == "active":
            service_info = "✅ Bot configured as service"
        else:
            service_info = "⚠️ Bot running manually"
        
        bot_pid = SystemMonitor.run_command("pgrep -f 'python3.*bot.py'")
        
        status_msg = f"""🤖 *BOT STATUS*

{service_info}
🔄 PID: `{bot_pid if bot_pid else 'Not found'}`
📊 Bot uptime: `{int(time.time() - start_time)} seconds`
🔧 Automatic reboots: `{'✅ ACTIVATED' if service_status == 'active' else '❌ DEACTIVATED'}`

*Useful commands:*
• `sudo systemctl status telegram-bot.service`
• `sudo systemctl restart telegram-bot.service`
• `sudo systemctl enable telegram-bot.service`"""
        
        await update.message.reply_text(status_msg, parse_mode='Markdown')
        
    except Exception as e:
        logging.error(f"Error in botstatus: {e}")
        await update.message.reply_text("❌ Error checking bot status", parse_mode='Markdown')

# ===== BOT COMMANDS =====

async def command_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles the /start command"""
    await send_help_menu(update, context)

async def send_help_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Shows the help menu"""
    welcome_message = """🎛️ *CONTROL PANEL - Raspberry Pi* 🖥️

*Available commands:*

🖥️  `/monitor`   - Real-time monitor (30 sec)
🔍  `/cpudetail` - Detailed CPU and cores info
📊  `/status`    - Complete system status
💾  `/memory`    - Detailed memory and storage info
🌐  `/network`   - Complete network and SSH information
🔍  `/ports`     - Detailed list of open ports
🔄  `/resetnet`  - Reset network statistics
📦  `/updatestatus` - View pending updates
🔄  `/update`    - Update system (apt update & upgrade)
🔔  `/alerts`    - Activate/deactivate alerts
📡  `/services`  - Services and Docker status
🔄  `/reboot`    - Reboot system (with confirmation)
⏹️  `/shutdown`  - Shutdown system (with confirmation)
❓  `/help`      - This help menu

*New features:*
• 💾 Unified memory and storage information
• 📦 System update management
• 🛡️ Security update detection
• 🚀 Real-time network speed

*How to use?*
Use the menu commands or type directly the command you need."""

    await update.message.reply_text(welcome_message, parse_mode='Markdown')

async def command_help(update: Update, context: ContextTypes.DEFAULT_TYPE): # Help command
    await send_help_menu(update, context)

async def command_monitor(update: Update, context: ContextTypes.DEFAULT_TYPE): # Monitoring
    global MONITOR_ACTIVE, MONITOR_TASK
    
    if MONITOR_ACTIVE:
        await update.message.reply_text("📊 *Monitor is already running*", parse_mode='Markdown')
        return
    
    MONITOR_ACTIVE = True
    await update.message.reply_text(
        "🖥️ *STARTING REAL-TIME MONITOR* ⏱️\n*Duration:* 30 seconds\n*Update:* every 3 seconds\n\nTo stop: send `stop`", 
        parse_mode='Markdown'
    )
    
    MONITOR_TASK = asyncio.create_task(monitor_live(update, context, 30))

async def monitor_live(update: Update, context: ContextTypes.DEFAULT_TYPE, duration: int): # Monitor improvements
    global MONITOR_ACTIVE
    monitor = SystemMonitor()
    start_time = time.time()
    message_id = None

    try:
        while time.time() < start_time + duration and MONITOR_ACTIVE:
            temp = monitor.get_temperature()
            cpu_info = monitor.get_cpu_usage_per_core()
            cpu_usage = cpu_info['total']
            ram_info = monitor.get_ram_usage()
            disk_info = monitor.get_disk_usage()
            load = monitor.get_load_average()
            uptime = monitor.get_uptime()
            fan = monitor.get_fan_state()
            network = monitor.get_network_usage()
            processes = monitor.get_top_processes()
            
            cores_info = ""
            if cpu_info['cores']:
                for i, core_usage in enumerate(cpu_info['cores']):
                    cores_info += f"{i}️⬚ {core_usage:.1f}% "
            
            cpu_top = "\n".join([f"{i}️⃣ {name} 🚀 {usage:.1f}%" 
                            for i, (name, usage) in enumerate(processes['cpu'][:3], 1)]) or "📭 No processes"
            ram_top = "\n".join([f"{i}️⃣ {name} 💾 {usage:.1f}%" 
                            for i, (name, usage) in enumerate(processes['ram'][:3], 1)]) or "📭 No processes"
            
            remaining = int(start_time + duration - time.time())
            
            monitor_msg = f"""🖥️ *LIVE MONITOR* ⏱️ {remaining}s

🌡️  *Temp:* {temp}°C | 🌀 {fan}
💻  *CPU:* {cpu_usage:.1f}% | 🎯 *Max Core:* {cpu_info['max_core']:.1f}%
📊  *Load Avg:* {load}
🧠  {monitor.get_progress_bar(ram_info['percent'])} *RAM:* {ram_info['percent']}%
💿  {monitor.get_progress_bar(disk_info['percent'])} *HDD:* {disk_info['percent']}%
🌐  *Network:* {network['interface']} | 🏠 {network['ip_local']}
🚀  *Speed:* ⬇️ {network['rx_speed']:.2f} MB/s ⬆️ {network['tx_speed']:.2f} MB/s
🕒  *Uptime:* {uptime}

🎯 *CPU Cores:* {cores_info}

🔝 *Top processes 💻 CPU*
{cpu_top}

🔝 *Top processes 🧠 RAM*  
{ram_top}

*Updated:* {datetime.now().strftime('%H:%M:%S')}"""
            
            try:
                if message_id:
                    await context.bot.edit_message_text(
                        chat_id=update.effective_chat.id,
                        message_id=message_id,
                        text=monitor_msg,
                        parse_mode='Markdown'
                    )
                else:
                    sent = await update.message.reply_text(monitor_msg, parse_mode='Markdown')
                    message_id = sent.message_id
            except Exception as e:
                logging.warning(f"Error updating message: {e}")
                sent = await update.message.reply_text(monitor_msg, parse_mode='Markdown')
                message_id = sent.message_id
            
            await asyncio.sleep(3)  # Fixed to 3 seconds as in the comment
            
    except asyncio.CancelledError:
        pass
    finally:
        MONITOR_ACTIVE = False
        if message_id:
            try:
                await context.bot.edit_message_text(
                    chat_id=update.effective_chat.id,
                    message_id=message_id,
                    text="📊 *Real-time monitor finished*",
                    parse_mode='Markdown'
                )
            except:
                await update.message.reply_text("📊 *Real-time monitor finished*", parse_mode='Markdown')

async def command_status(update: Update, context: ContextTypes.DEFAULT_TYPE): # Status
    monitor = SystemMonitor()
    
    temp = monitor.get_temperature()
    cpu_info = monitor.get_cpu_usage_per_core()
    ram_info = monitor.get_ram_usage()
    disk_info = monitor.get_disk_usage()
    load = monitor.get_load_average()
    uptime = monitor.get_uptime()
    fan = monitor.get_fan_state()
    
    cpu_bar = monitor.get_progress_bar(cpu_info['total'])
    ram_bar = monitor.get_progress_bar(ram_info['percent'])
    disk_bar = monitor.get_progress_bar(disk_info['percent'])
    
    cpu_emoji = monitor.get_usage_emoji(cpu_info['total'])
    ram_emoji = monitor.get_usage_emoji(ram_info['percent'])
    disk_emoji = monitor.get_usage_emoji(disk_info['percent'])
    temp_emoji = "🔴" if temp > 70 else "🟡" if temp > 60 else "🟢"
    
    status_msg = f"""📊 *COMPLETE SYSTEM STATUS*

🌡️ *TEMPERATURE:* {temp}°C {temp_emoji}

🌀 *FAN:* {fan}

*💻 CPU:* {cpu_info['total']:.1f}%{cpu_emoji} 
{cpu_bar} {cpu_info['total']:.1f}%

*🧠 RAM:* {ram_info['percent']}%{ram_emoji} 
{ram_bar} {ram_info['percent']}%
💾 *Memory:* {ram_info['used']} used / {ram_info['free']} free / {ram_info['available']} available
📊 *Total RAM:* {ram_info['total']}

*💿 HDD:* {disk_info['percent']}%{disk_emoji} 
{disk_bar} {disk_info['percent']}%
💿 *Space:* {disk_info['used']} used / {disk_info['free']} free
📦 *Total disk:* {disk_info['total']}

📈 *Load Average:* {load}
🕒 *Uptime:* {uptime}
🔔 *Alerts:* {'✅ ACTIVE' if ALERTS_ENABLED else '❌ INACTIVE'}

*Updated:* {datetime.now().strftime('%H:%M:%S')}"""
    
    await update.message.reply_text(status_msg, parse_mode='Markdown')

async def command_network(update: Update, context: ContextTypes.DEFAULT_TYPE): # Network
    """Handles the /network command - Network information"""
    monitor = SystemMonitor()
    network = monitor.get_network_usage()
    services = monitor.get_network_services()
    firewall_status = monitor.get_firewall_status()
    
    total_rx_gb = network['total_rx_reset'] / (1024 * 1024 * 1024)
    total_tx_gb = network['total_tx_reset'] / (1024 * 1024 * 1024)
    
    connections = SystemMonitor.run_command("ss -t state established | wc -l") or "N/A"
    remote_connections = SystemMonitor.run_command("ss -t state established 'sport != :ssh' | awk '{print $4}' | cut -d: -f1 | sort -u | wc -l") or "N/A"
    
    ssh_info = ""
    for port in services['ssh_ports']:
        ssh_info += f"• 🔐 SSH Port `{port}`: `ssh {network['ip_local']} -p {port}`\n"
        if network['public_ip'] != "Not available":
            ssh_info += f"  🌍 Remote: `ssh {network['public_ip']} -p {port}`\n"
    
    services_info = ""
    if services['active_services']:
        for service in services['active_services'][:6]:
            services_info += f"• {service}\n"
    else:
        services_info = "• No common services detected\n"
    
    reset_elapsed = time.time() - NETWORK_STATS.get('reset_time', time.time())
    hours = int(reset_elapsed // 3600)
    minutes = int((reset_elapsed % 3600) // 60)
    time_since_reset = f"{hours}h {minutes}m" if hours > 0 else f"{minutes}m"
    
    network_msg = f"""🌐 *REAL-TIME NETWORK INFORMATION*

📡 *INTERFACE AND CONNECTION*
• 🌐 Interface: `{network['interface']}`
• 🏠 Local IP: `{network['ip_local']}`
• 🌍 Public IP: `{network['public_ip']}`
• 🛡️ Firewall: {firewall_status}

🚀 *CURRENT SPEED*
• ⬇️ Download: `{network['rx_speed']:.2f} MB/s`
• ⬆️ Upload: `{network['tx_speed']:.2f} MB/s`

📊 *STATISTICS SINCE RESET* ({time_since_reset})
• ⬇️ Downloaded: `{total_rx_gb:.2f} GB`
• ⬆️ Uploaded: `{total_tx_gb:.2f} GB`
• 🔗 Active connections: `{connections}`
• 🌍 Remote IPs connected: `{remote_connections}`
• 🚪 Listening ports: `{services['total_listening']}`

🔐 *SSH CONNECTION*
{ssh_info if ssh_info else "• ⚠️ No SSH service detected"}

📋 *DETECTED SERVICES*
{services_info}

💡 *RECOMMENDATIONS*
• Use `/resetnet` to reset counters
• Monitor with `/monitor` to see live speed

*Updated:* {datetime.now().strftime('%H:%M:%S')}"""
    
    await update.message.reply_text(network_msg, parse_mode='Markdown')

async def command_memory(update: Update, context: ContextTypes.DEFAULT_TYPE): # Memory command
    """Handles the /memory command - Detailed memory and storage information"""
    monitor = SystemMonitor()
    ram_info = monitor.get_ram_usage()
    disk_info = monitor.get_disk_usage()
    
    try:
        swap_cmd = "free -b | grep Swap"
        swap_output = SystemMonitor.run_command(swap_cmd)
        
        if swap_output:
            swap_parts = swap_output.split()
            if len(swap_parts) >= 4 and swap_parts[1] != "0":
                swap_total_bytes = int(swap_parts[1])
                swap_used_bytes = int(swap_parts[2])
                swap_free_bytes = int(swap_parts[3])
                swap_percent = int((swap_used_bytes / swap_total_bytes) * 100) if swap_total_bytes > 0 else 0
                
                def format_bytes(bytes_size):
                    for unit in ['B', 'KB', 'MB', 'GB']:
                        if bytes_size < 1024.0:
                            return f"{bytes_size:.1f} {unit}"
                        bytes_size /= 1024.0
                    return f"{bytes_size:.1f} TB"
                
                swap_total = format_bytes(swap_total_bytes)
                swap_used = format_bytes(swap_used_bytes)
                swap_free = format_bytes(swap_free_bytes)
            else:
                swap_total, swap_used, swap_free, swap_percent = "0B", "0B", "0B", 0
        else:
            swap_total, swap_used, swap_free, swap_percent = "Not detected", "N/A", "N/A", 0
            
    except Exception as e:
        logging.error(f"Error getting swap: {e}")
        swap_total, swap_used, swap_free, swap_percent = "Error", "N/A", "N/A", 0
    
    ram_bar = monitor.get_progress_bar(ram_info['percent'])
    swap_bar = monitor.get_progress_bar(swap_percent)
    disk_bar = monitor.get_progress_bar(disk_info['percent'])
    
    ram_emoji = monitor.get_usage_emoji(ram_info['percent'])
    swap_emoji = monitor.get_usage_emoji(swap_percent)
    disk_emoji = monitor.get_usage_emoji(disk_info['percent'])
    
    memory_msg = f"""💾 *DETAILED MEMORY AND STORAGE INFORMATION*

{ram_emoji} *🧠 RAM MEMORY:* {ram_info['percent']}%
{ram_bar} {ram_info['percent']}%

*RAM Breakdown:*
• 📊 Total: {ram_info['total']}
• 🟡 In use: {ram_info['used']}
• 🟢 Free: {ram_info['free']}
• 🔵 Available: {ram_info['available']}

{swap_emoji} *💽 SWAP MEMORY:* {swap_percent}%
{swap_bar} {swap_percent}%

*Swap Breakdown:*
• 📊 Total: {swap_total}
• 🟡 In use: {swap_used}
• 🟢 Free: {swap_free}

{disk_emoji} *💿 STORAGE:* {disk_info['percent']}%
{disk_bar} {disk_info['percent']}%

*Disk Breakdown:*
• 📊 Total: {disk_info['total']}
• 🟡 In use: {disk_info['used']}
• 🟢 Free: {disk_info['free']}
• 📈 Usage: {disk_info['percent']}%

*Updated:* {datetime.now().strftime('%H:%M:%S')}"""
    
    await update.message.reply_text(memory_msg, parse_mode='Markdown')

async def command_ports(update: Update, context: ContextTypes.DEFAULT_TYPE): # Ports command
    try:
        monitor = SystemMonitor()
        network_info = monitor.get_network_usage()
        
        cmd = "ss -tulpn | grep LISTEN"
        ports_output = SystemMonitor.run_command(cmd)
        
        if not ports_output:
            await update.message.reply_text("📭 *No ports listening*", parse_mode='Markdown')
            return
        
        ports_info = f"""🔍 *OPEN PORTS - COMPLETE ANALYSIS*

🌐 *Network Information:*
• 🏠 Local IP: `{network_info['ip_local']}`
• 🌍 Public IP: `{network_info['public_ip']}`
• 📡 Interface: `{network_info['interface']}`

📋 *Detected Ports:*
"""
        
        services_detected = []
        for line in ports_output.split('\n'):
            if 'LISTEN' in line and 'tcp' in line:
                parts = line.split()
                if len(parts) >= 6:
                    protocol = 'TCP'
                    address = parts[4]
                    process = parts[5] if 'users' in parts[5] else "System"
                    
                    if ':' in address:
                        # Extract IP and port
                        if '[' in address:  # IPv6
                            ip_part, port_part = address.split(']:')
                            ip = ip_part + ']'
                        else:  # IPv4
                            ip, port = address.rsplit(':', 1)
                        
                        port = port if 'port' in locals() else port_part
                        
                        # Determine access type
                        access_type = "🔒 Local" if ip in ['127.0.0.1', 'localhost', '::1'] else "🌍 Public" if ip in ['0.0.0.0', '*', '::'] else "🔗 Specific"
                        
                        service_info = f"""• 🚪 *Port {port}/{protocol}* ({access_type})
    📍 Address: `{address}`
    ⚙️ Process: `{process}`
"""
                        if network_info['public_ip'] != "Not available" and access_type == "🌍 Public":
                            service_info += f"  🌐 Remote access: `{network_info['public_ip']}:{port}`\n"
                        elif access_type == "🔒 Local":
                            service_info += f"  🏠 Local access: `{network_info['ip_local']}:{port}`\n"
                        
                        services_detected.append(service_info)
        
        for service in services_detected[:20]:
            ports_info += service + "\n"
        
        if len(services_detected) > 20:
            ports_info += f"\n📊 ... and {len(services_detected) - 20} more ports\n"
        
        ports_info += f"\n💡 *Total listening ports:* `{len(services_detected)}`"
        ports_info += f"\n🕒 *Updated:* {datetime.now().strftime('%H:%M:%S')}"
        
        if len(ports_info) > 4000:
            half = len(ports_info) // 2
            part1 = ports_info[:half] + "\n\n... (continues)"
            part2 = ports_info[half:] + "\n\n... (end)"
            
            await update.message.reply_text(part1, parse_mode='Markdown')
            await update.message.reply_text(part2, parse_mode='Markdown')
        else:
            await update.message.reply_text(ports_info, parse_mode='Markdown')
        
    except Exception as e:
        logging.error(f"Error in command_ports: {e}")
        await update.message.reply_text("❌ Error getting port information", parse_mode='Markdown')

async def command_reset_network(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Resets network statistics"""
    global NETWORK_STATS
    
    interface = SystemMonitor.run_command("ip route | awk '/default/ {print $5; exit}'") or 'eth0'
    rx_bytes = SystemMonitor.run_command(f"cat /sys/class/net/{interface}/statistics/rx_bytes 2>/dev/null") or "0"
    tx_bytes = SystemMonitor.run_command(f"cat /sys/class/net/{interface}/statistics/tx_bytes 2>/dev/null") or "0"
    
    NETWORK_STATS = {
        'last_rx_bytes': int(rx_bytes),
        'last_tx_bytes': int(tx_bytes),
        'last_check_time': time.time(),
        'current_rx_speed': 0,
        'current_tx_speed': 0,
        'total_rx_since_reset': 0,
        'total_tx_since_reset': 0,
        'reset_time': time.time()
    }
    
    reset_time = datetime.now().strftime('%H:%M:%S')
    await update.message.reply_text(
        f"🔄 *Network statistics completely reset*\n\n• 📊 Data counters restarted\n• 🚀 Speeds will be calculated from zero\n• ⏰ Reset time: {reset_time}",
        parse_mode='Markdown'
    )

async def command_updatestatus(update: Update, context: ContextTypes.DEFAULT_TYPE): # Status command
    """Shows pending updates more accurately"""
    try:
        SystemMonitor.run_command("sudo apt update > /dev/null 2>&1")
        
        upgradable_cmd = "apt list --upgradable 2>/dev/null | grep -c upgradable"
        upgradable_result = SystemMonitor.run_command(upgradable_cmd)
        upgradable_count = int(upgradable_result) if upgradable_result else 0
        
        security_updates_cmd = "apt list --upgradable 2>/dev/null | grep -i security | wc -l"
        security_updates = SystemMonitor.run_command(security_updates_cmd)
        security_count = int(security_updates) if security_updates else 0
        
        status_msg = f"""📦 *DETAILED UPDATE STATUS*

• 🔄 Pending updates: `{upgradable_count} packages`
• 🛡️ Security updates: `{security_count} packages`
        
*Available commands:*
• `/updatestatus` - See this summary
• `/update` - Execute complete update
• `/reboot` - Reboot if necessary

*Recommendations:*
{f"• ⚠️ You have {upgradable_count} pending updates" if upgradable_count > 0 else "• ✅ Your system is updated"}
{f"• 🛡️ {security_count} security updates available" if security_count > 0 else "• ✅ No critical security updates"}
{f"• 🎯 Use `/update` to update" if upgradable_count > 0 else "• 🏆 System up to date"}"""

        await update.message.reply_text(status_msg, parse_mode='Markdown')
        
    except Exception as e:
        logging.error(f"Error in updatestatus: {e}")
        await update.message.reply_text(
            "❌ *ERROR CHECKING UPDATES*\n\nExecute manually: `sudo apt update && apt list --upgradable`",
            parse_mode='Markdown'
        )

async def command_update(update: Update, context: ContextTypes.DEFAULT_TYPE): # Update command
    """Handles the /update command improved"""
    if str(update.effective_user.id) != TELEGRAM_CHAT_ID:
        await update.message.reply_text("❌ *ACCESS DENIED*", parse_mode='Markdown')
        return
    
    update_msg = """⚠️ *CONFIRM SYSTEM UPDATE* ⚠️

*This process:*
• 📦 Will update the package list
• ⬆️ Will apply all available updates
• 🗑️ Will clean unnecessary packages
• ⏱️ May take 5-15 minutes
• 🔄 May require subsequent reboot

*Reply:*
• `SI` to confirm update
• `NO` to cancel

*You have 30 seconds to confirm*"""
    
    await update.message.reply_text(update_msg, parse_mode='Markdown')
    context.user_data['waiting_update_confirmation'] = True

async def command_alerts(update: Update, context: ContextTypes.DEFAULT_TYPE): # Activate/deactivate alerts command
    """Handles the /alerts command - Activate/deactivate alerts"""
    global ALERTS_ENABLED
    
    ALERTS_ENABLED = not ALERTS_ENABLED
    
    if ALERTS_ENABLED:
        alert_msg = """🔔 *ALERTS ACTIVATED*

You will receive notifications when:
• 🌡️ Temperature > 65°C
• 💻 CPU > 90%
• 💾 RAM > 90% 
• 💿 Disk > 90%

To deactivate: /alerts"""
    else:
        alert_msg = """🔔 *ALERTS DEACTIVATED*

You will no longer receive automatic notifications for:
• 🌡️ High temperature
• 💻 High CPU usage
• 💾 High RAM usage
• 💿 Almost full disk

To activate: /alerts"""
    
    await update.message.reply_text(alert_msg, parse_mode='Markdown')

async def command_services(update: Update, context: ContextTypes.DEFAULT_TYPE): # Services command
    monitor = SystemMonitor()
    services_status = monitor.get_services_status()
    
    services_msg = f"""📡 *SERVICES AND DOCKER STATUS*

{services_status}

*Updated:* {datetime.now().strftime('%H:%M:%S')}"""

    await update.message.reply_text(services_msg, parse_mode='Markdown')

async def command_reboot(update: Update, context: ContextTypes.DEFAULT_TYPE): # Improved reboot 04/10/2025
    if str(update.effective_user.id) != TELEGRAM_CHAT_ID:
        await update.message.reply_text("❌ *ACCESS DENIED*", parse_mode='Markdown')
        return
    
    reboot_msg = """⚠️ *CONFIRM SYSTEM REBOOT* ⚠️

*This process:*
• 🔄 Will reboot the entire system
• ⏰ Will take 1-2 minutes
• 📱 Will cut bot connection temporarily
• 🔌 Will reestablish all services

*You will receive a notification when the system is operational.*

*Reply:*
• `SI` to confirm reboot
• `NO` to cancel

*You have 30 seconds to confirm*"""
    
    await update.message.reply_text(reboot_msg, parse_mode='Markdown')
    context.user_data['waiting_reboot_confirmation'] = True

async def command_shutdown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handles the /shutdown command - Shutdown system"""
    shutdown_msg = """⚠️ *CONFIRM SHUTDOWN* ⚠️

Are you sure you want to shutdown the system?

*Reply:*
• `SI` to confirm shutdown  
• `NO` to cancel

*You have 30 seconds to confirm*"""
    
    await update.message.reply_text(shutdown_msg, parse_mode='Markdown')

async def command_debug(update: Update, context: ContextTypes.DEFAULT_TYPE): # Debug command
    debug_info = f"""🔧 *REBOOT SYSTEM DIAGNOSTICS*

• 📁 Flag file exists: `{os.path.exists(REBOOT_FLAG_FILE)}`
• 📍 Flag path: `{REBOOT_FLAG_FILE}`
• 🤖 Bot running: `True`
• 🔔 Alerts enabled: `{ALERTS_ENABLED}`
• 📊 Service status: `{SystemMonitor.run_command('systemctl is-active telegram-bot.service')}`

*Test commands:*
• View flag: `cat {REBOOT_FLAG_FILE}`
• Service: `sudo systemctl status telegram-bot.service`
• Logs: `journalctl -u telegram-bot.service -n 20`"""

    if os.path.exists(REBOOT_FLAG_FILE):
        try:
            with open(REBOOT_FLAG_FILE, 'r') as f:
                content = f.read().strip()
            debug_info += f"\n• 📝 Flag content: `{content}`"
        except Exception as e:
            debug_info += f"\n• ❌ Error reading flag: `{e}`"
    
    await update.message.reply_text(debug_info, parse_mode='Markdown')

async def setup_bot_commands(application): # Commands info
    commands = [
        ("start", "🚀 Start system"),
        ("monitor", "🖥️ Live monitor"),
        ("status", "📊 Complete status"),
        ("memory", "💾 Memory info"),
        ("network", "🌐 Network and SSH complete"),
        ("ports", "🔍 Open ports"),
        ("alerts", "🔔 Alert management"),
        ("services", "📡 Services and Docker"),
        ("reboot", "🔄 Reboot system"),
        ("shutdown", "⏹️ Shutdown system"),
        ("help", "❓ Complete help")
    ]
    
    await application.bot.set_my_commands(commands)

async def command_forcecheck(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Forces an immediate alert check"""
    global LAST_ALERT_TIME
    
    old_cooldown = LAST_ALERT_TIME
    LAST_ALERT_TIME = 0
    
    checking_msg = await update.message.reply_text("🔍 *Immediate check in progress...*", parse_mode='Markdown')
    
    try:
        await background_alert_checker(context)
        
        if LAST_ALERT_TIME > 0:
            await checking_msg.edit_text("✅ *Check completed - Alerts sent*", parse_mode='Markdown')
        else:
            await checking_msg.edit_text("✅ *Check completed - No alerts*", parse_mode='Markdown')
            
    except Exception as e:
        await checking_msg.edit_text(f"❌ *Error in check:* {str(e)}", parse_mode='Markdown')
        LAST_ALERT_TIME = old_cooldown

async def command_alertstatus(update: Update, context: ContextTypes.DEFAULT_TYPE): # Confirm alerts
    global ALERTS_ENABLED, LAST_ALERT_TIME, ALERT_HISTORY
    
    monitor = SystemMonitor()
    temp = monitor.get_temperature()
    cpu = monitor.get_cpu_usage()
    ram_info = monitor.get_ram_usage()
    disk_info = monitor.get_disk_usage()
    
    time_since_last_alert = time.time() - LAST_ALERT_TIME
    cooldown_remaining = max(0, ALERT_COOLDOWN - time_since_last_alert)
    
    cpu_avg = sum(ALERT_HISTORY['cpu']) / len(ALERT_HISTORY['cpu']) if ALERT_HISTORY['cpu'] else 0
    temp_avg = sum(ALERT_HISTORY['temp']) / len(ALERT_HISTORY['temp']) if ALERT_HISTORY['temp'] else 0
    
    status_msg = f"""🔔 *ALERT SYSTEM STATUS*

• 🔔 Active alerts: `{"✅ YES" if ALERTS_ENABLED else "❌ NO"}`
• ⏰ Last alert: `{int(time_since_last_alert)} seconds ago`
• 🕒 Cooldown remaining: `{int(cooldown_remaining)} seconds`
• 📊 Check interval: `Every 5 minutes`
• 📈 History size: `{len(ALERT_HISTORY['cpu'])}/3 measurements`

*📊 CURRENT VALUES AND TRENDS:*
• 🌡️ Temperature: `{temp}°C` (avg: `{temp_avg:.1f}°C`) → Threshold: `70°C`
• 💻 CPU: `{cpu:.1f}%` (avg: `{cpu_avg:.1f}%`) → Threshold: `85%`
• 💾 RAM: `{ram_info['percent']}%` → Threshold: `85%`
• 💿 Disk: `{disk_info['percent']}%` → Threshold: `85%`

*🚨 TRIGGERED CONDITIONS:*
{'• 🌡️ **HIGH TEMPERATURE**' if temp > 70 else ''}
{'• 💻 **HIGH CPU**' if cpu > 85 else ''}
{'• 💾 **HIGH RAM**' if ram_info['percent'] > 85 else ''}
{'• 💿 **FULL DISK**' if disk_info['percent'] > 85 else ''}

*⚡ QUICK COMMANDS:*
• `/forcecheck` - Immediate check
• `/alerts` - Activate/deactivate alerts"""

    await update.message.reply_text(status_msg, parse_mode='Markdown')

async def command_cpudetail(update: Update, context: ContextTypes.DEFAULT_TYPE): # Detailed CPU command 04/10/2025
    monitor = SystemMonitor()
    
    cpu_info = monitor.get_cpu_usage_per_core()
    temp = monitor.get_temperature()
    load = monitor.get_load_average()
    processes = monitor.get_top_processes()
    
    arch_cmd = "lscpu | grep 'Model name\\|CPU(s)\\|Thread(s) per core\\|Core(s) per socket'"
    arch_info = SystemMonitor.run_command(arch_cmd)
    
    cores_detail = ""
    if cpu_info['cores']:
        for i, core_usage in enumerate(cpu_info['cores']):
            emoji = "🔴" if core_usage > 90 else "🟡" if core_usage > 70 else "🟢"
            cores_detail += f"{emoji} Core {i}: {core_usage:.1f}%\n"
    
    detail_msg = f"""🔍 *DETAILED CPU INFORMATION*

📊 *CURRENT USAGE:* {cpu_info['total']:.1f}%
🎯 *MAX PER CORE:* {cpu_info['max_core']:.1f}%
🌡️ *TEMPERATURE:* {temp}°C
📈 *LOAD AVERAGE:* {load}

*BREAKDOWN BY CORES:*
{cores_detail}

*TOP 5 PROCESSES CONSUMING CPU:*
"""
    
    for i, (name, usage) in enumerate(processes['cpu'][:5], 1):
        detail_msg += f"{i}️⃣ `{name}` → {usage:.1f}%\n"
    
    if arch_info:
        detail_msg += f"\n*ARCHITECTURE:*\n```{arch_info}```"
    
    detail_msg += f"\n*Updated:* {datetime.now().strftime('%H:%M:%S')}"
    
    await update.message.reply_text(detail_msg, parse_mode='Markdown')

#------------------------- Commands ------------------------------------------------------

def main():
    if os.path.exists(REBOOT_FLAG_FILE):
        print("🔄 Detected recent reboot, notifying...")
    
    try:
        application = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()
        
        job_queue = application.job_queue
        if job_queue:
            job_queue.run_repeating(background_alert_checker, interval=300, first=10)
            job_queue.run_repeating(check_reboot_status, interval=30, first=15)  # Increased first to wait for complete boot
            
        application.add_handler(CommandHandler("start", command_start))
        application.add_handler(CommandHandler("help", command_help))
        application.add_handler(CommandHandler("monitor", command_monitor))
        application.add_handler(CommandHandler("status", command_status))
        application.add_handler(CommandHandler("memory", command_memory))
        application.add_handler(CommandHandler("network", command_network))
        application.add_handler(CommandHandler("ports", command_ports))
        application.add_handler(CommandHandler("resetnet", command_reset_network))
        application.add_handler(CommandHandler("updatestatus", command_updatestatus))
        application.add_handler(CommandHandler("update", command_update))
        application.add_handler(CommandHandler("alerts", command_alerts))
        application.add_handler(CommandHandler("services", command_services))
        application.add_handler(CommandHandler("reboot", command_reboot))
        application.add_handler(CommandHandler("shutdown", command_shutdown))
        application.add_handler(CommandHandler("debug", command_debug))
        application.add_handler(CommandHandler("forcecheck", command_forcecheck))
        application.add_handler(CommandHandler("alertstatus", command_alertstatus))
        application.add_handler(CommandHandler("cpudetail", command_cpudetail))
        # application.add_handler(CommandHandler("cputest", command_cputest)) # New, coming soon
        application.add_handler(MessageHandler(filters.TEXT & filters.Regex(r'^(stop|Stop|STOP)$'), handle_stop))
        application.add_handler(MessageHandler(filters.TEXT & filters.Regex(r'^(SI|NO|si|no|Si|No)$'), handle_confirmation))
        
        application.post_init = setup_bot_commands
        
        print("🤖 Bot starting with valid token...")
        print("🔧 Implemented features:")
        print("   • ✅ Automatic reboot notifications")
        print("   • ✅ Improved update management")
        print("   • ✅ Real-time update progress")
        print("   • ✅ Accurate detection of pending updates")
        
        application.run_polling()
        
    except Exception as e:
        logging.error(f"Fatal error starting bot: {e}")
        print(f"❌ Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
