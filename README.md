# System Monitor Telegram Bot

A powerful Telegram bot for monitoring and managing Linux systems (Raspberry Pi, servers, etc.) with real-time statistics, alerts, and remote management capabilities.

## ✨ Features

- 📊 Real-time system monitoring (CPU, RAM, Disk, Temperature)
- 🌐 Network statistics and port analysis
- 🐋 Docker container monitoring
- 🔔 Smart alert system with thresholds
- ⚡ Remote system management
- 🔄 Auto-reconnect after reboot

## 🚀 Quick Start

1. **Clone the repository**
   ```bash
   git clone https://github.com/dAvzdev/system-monitor-bot.git
   cd system-monitor-bot

2. Install dependencies
   ```bash
   pip install -r requirements.txt

3. Configure your bot
   ```bash
   cp config.example.py config.py
   # Edit config.py with your credentials

4. Run the bot 🤖
   ```bash
   python bot.py

🛠️ Configuration 🛠️ 
Using Environment Variables (Recommended)

	export TELEGRAM_BOT_TOKEN="your_bot_token"
	export TELEGRAM_CHAT_ID="your_chat_id"

Alternative: Config File
Create config.py:

	BOT_TOKEN = "your_bot_token_here"
	CHAT_ID = "your_chat_id_here"

📖 Usage
Start with /start to see available commands:

	/status    - System overview
	/monitor   - Real-time monitoring
	/network   - Network information  
	/reboot    - Reboot system (with confirmation)
	/update    - System updates

🐋 Docker Support
The bot includes Docker container monitoring. Use /services to see running containers.

🔔 Alert System
Smart alerts for:

High temperature (>70°C) 🌡️  

High CPU usage (>85%) 💻 

High RAM usage (>85%) 💾

Low disk space (>85% used) 💿

Toggle with /alerts command.

🤖 Bot Commands Menu
The bot includes a built-in command menu for easy access to all features.

🤝 Contributing
Contributions welcome! Please feel free to submit pull requests or open issues.
