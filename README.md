# Host-Based Intrusion Prevention System (HIPS)

## 📌 Project Overview
This project is a simple Host-Based Intrusion Prevention System (HIPS) developed using Python on Kali Linux. The system monitors activities on a host machine such as running processes and file changes, detects suspicious behavior, and takes preventive actions. The main goal of this project is to enhance system security by providing real-time monitoring and protection at the host level.

## 🎯 Objectives
- To monitor system processes and detect unusual or suspicious activities.
- To track file system changes in real time.
- To prevent potential threats before they cause damage to the system.

## 🛠️ Technologies Used
- Python 3
- psutil
- watchdog
- logging
- Kali Linux

## ⚙️ Features
- Real-time process monitoring
- File integrity monitoring
- Suspicious activity detection
- Logging of security events
- Basic prevention mechanism

## 📂 Project Structure
```
HIPS/
│── hips_engine.py
│── requirements.txt
│── README.md
```

## 🚀 Installation & Setup

1. Clone the repository:
```
git clone https://github.com/your-username/your-repo-name.git
```

2. Navigate to the project directory:
```
cd your-repo-name
```

3. Install required dependencies:
```
pip install -r requirements.txt
```

4. Run the program:
```
python hips_engine.py
```

## 🧠 How It Works
The system continuously monitors system processes using psutil and tracks file system changes using watchdog. If suspicious behavior is detected, it logs the activity and can take preventive action based on predefined rules.

## ⚠️ Limitations
- Basic rule-based detection
- Not suitable for enterprise-level deployment
- Requires manual configuration for advanced detection

## 🔮 Future Improvements
- Add machine learning-based anomaly detection
- Improve prevention mechanisms
- Add a graphical user interface (GUI)
- Expand rule-based detection

## 📄 License
This project is developed for educational purposes.
