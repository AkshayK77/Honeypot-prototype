# Basic implementation of a Honeypot

A sophisticated honeypot system that simulates a banking website to detect, analyze, and prevent brute force attacks. This project demonstrates advanced security concepts and attack pattern recognition.

## Features

### Security Features
- 🕵️ Honeypot login system that logs all attack attempts
- 🔒 Rate limiting to prevent brute force attacks
- 🌐 IP-based access control for admin interface
- 🔑 Password complexity validation
- 🚫 Account lockout mechanism
- 🔍 Attack pattern detection (SQL injection, command injection, etc.)
- 📍 Geolocation tracking of attack attempts

### Admin Dashboard
- 📊 Real-time attack statistics and visualizations
- 📝 Detailed logging of attack attempts
- 🗺️ Geolocation data for attacks
- 📈 Attack type distribution analysis
- 👤 Common usernames and passwords tracking
- 🔄 Live updates via API endpoints

## Technology Stack
- Python 3.x
- Flask Web Framework
- SQLAlchemy ORM
- SQLite Database
- Flask-Login for authentication
- Flask-Limiter for rate limiting
- Bootstrap 5 for UI
- Chart.js for visualizations

## Installation

1. Clone the repository:
```bash
git clone https://github.com/AkshayK77/Brute-Force-Prevention-Simulation.git
cd Brute-Force-Prevention-Simulation
```

2. Create and activate virtual environment:
```bash
python -m venv venv
# On Windows
.\venv\Scripts\activate
# On Unix/MacOS
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python init_db.py
```

5. Run the application:
```bash
python -m flask run
```

## Usage

### Dummy Bank Website (Honeypot)
- Access the dummy bank website at: `http://localhost:5000/`
- Try logging in at: `http://localhost:5000/dummy/login`
- All login attempts will be logged for analysis

### Admin Dashboard
- Access admin login at: `http://localhost:5000/admin/login`
- Default credentials:
  - Username: admin
  - Password: password123
- View attack statistics and logs in the dashboard

## Security Considerations

This project is designed for educational purposes and security research. If deploying in a production environment:

1. Change default admin credentials
2. Use a production-grade WSGI server
3. Enable HTTPS
4. Configure proper rate limiting storage backend
5. Use a more robust database system
6. Implement additional security measures

## Contributing

Feel free to contribute to this project:

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Akshay K - [GitHub Profile](https://github.com/AkshayK77) 
