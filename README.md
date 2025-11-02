# Security Scanner API

A comprehensive web vulnerability scanner application for detecting **XSS (Cross-Site Scripting)** and **SQL Injection (SQLi)** vulnerabilities. Built with FastAPI backend and modern Bootstrap 5 frontend.

🇷🇺 **For Russian documentation, see [README_RU.md](README_RU.md)**

## 🎯 Features

### Public Interface
- **URL Scanning**: Scan URLs for potential security vulnerabilities
- **Text Input Scanning**: Analyze text inputs for XSS and SQL injection patterns
- **Real-time Results**: Get instant feedback with detailed vulnerability reports
- **Risk Assessment**: Color-coded risk levels (Safe, Low, Medium, High)
- **Detailed Findings**: View specific patterns detected with severity levels

### Admin Panel (`/admin`)
- **Authentication**: Secure JWT-based admin login
- **Scan History**: View all past scans with detailed information
- **Statistics Dashboard**: Monitor scanning activity and threat detection
- **Rule Management**: Enable/disable scanning rules dynamically
- **System Logs**: View application logs for debugging and monitoring

## 🏗️ Architecture

The application follows **Object-Oriented Programming (OOP)** principles and **SOLID/DRY** best practices:

```
Security_Scanner_API/
├── admin/              # Admin authentication and authorization
│   └── auth.py
├── api/                # FastAPI route handlers
│   ├── public_routes.py
│   └── admin_routes.py
├── scanner/            # Vulnerability detection engine
│   └── vulnerability_scanner.py
├── storage/            # Database management (SQLite)
│   └── database.py
├── validators/         # Input validation and sanitization
│   └── input_validator.py
├── templates/          # HTML templates
│   ├── index.html
│   └── admin.html
├── main.py            # Application entry point
└── requirements.txt   # Python dependencies
```

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Setup Steps

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd Security_Scanner_API
   ```

2. **Create virtual environment** (recommended):
   ```bash
   python -m venv venv
   
   # On Windows
   venv\Scripts\activate
   
   # On Linux/Mac
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**:
   ```bash
   python main.py
   ```

   Or using uvicorn directly:
   ```bash
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```

5. **Access the application**:
   - Main scanner: http://localhost:8000
   - Admin panel: http://localhost:8000/admin
   - API docs: http://localhost:8000/docs

## 📝 Default Admin Credentials

**Для входа в админ-панель используйте следующие учетные данные:**

- **Логин (Username)**: `admin`
- **Пароль (Password)**: `admin123`

**URL админ-панели**: http://localhost:8000/admin

⚠️ **Важно**: Обязательно смените пароль администратора перед использованием в продакшене!

**Как изменить пароль**:
1. Используйте скрипт `generate_password_hash.py` для генерации нового хеша пароля
2. Обновите пароль в базе данных или создайте нового пользователя

## 🔧 Configuration

### Database
The application uses SQLite by default. The database file (`security_scanner.db`) will be created automatically on first run.

### Security Settings
- JWT secret key is set in `admin/auth.py` (change in production!)
- Token expiration: 30 minutes
- Password hashing: bcrypt

## 📊 API Endpoints

### Public Endpoints

- `POST /api/scan` - Scan input for vulnerabilities
  ```json
  {
    "input_data": "http://example.com?q=<script>alert('xss')</script>",
    "scan_type": "url"
  }
  ```

- `GET /api/health` - Health check

### Admin Endpoints (Requires Authentication)

- `POST /api/admin/login` - Authenticate admin user
- `GET /api/admin/scan-history` - Get scan history
- `GET /api/admin/statistics` - Get application statistics
- `GET /api/admin/rules` - Get scanning rules
- `PUT /api/admin/rules/{id}` - Update scanning rule
- `GET /api/admin/logs` - Get system logs

## 🛡️ Security Features

### Input Validation
- URL format validation
- Text length limits
- Input sanitization for safe storage
- HTML escaping to prevent XSS in stored data

### Vulnerability Detection

#### XSS Detection Patterns:
- Script tag detection (`<script>`)
- JavaScript protocol (`javascript:`)
- Event handlers (`onclick`, `onerror`, etc.)
- Iframe tags
- SVG with embedded scripts
- And more...

#### SQL Injection Detection Patterns:
- UNION SELECT statements
- Boolean-based SQL injection
- SQL command injection (DROP, DELETE, etc.)
- SQL comment delimiters (`--`, `/* */`)
- SQL functions and procedures
- And more...

## 🎨 UI Features

### Main Interface
- Modern, responsive Bootstrap 5 design
- Gradient backgrounds and smooth animations
- Color-coded risk indicators
- Detailed vulnerability reports
- Interactive finding cards

### Admin Panel
- Dark theme for professional appearance
- Statistics dashboard with visual cards
- Sortable and filterable tables
- Real-time rule management
- Comprehensive logging interface

## 🔒 Security Best Practices

1. **Input Sanitization**: All user inputs are sanitized before storage
2. **Password Hashing**: Bcrypt for secure password storage
3. **JWT Authentication**: Secure token-based admin authentication
4. **SQL Injection Prevention**: Parameterized queries and input validation
5. **XSS Prevention**: HTML escaping and content security measures

## 📈 Future Enhancements

- Support for more vulnerability types (CSRF, XXE, etc.)
- Export scan reports (PDF, JSON, CSV)
- Email notifications for high-risk findings
- Custom rule creation through admin panel
- API rate limiting
- User role management
- Scan scheduling

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

This tool is for **educational and authorized testing purposes only**. Do not use this tool to scan systems without explicit permission. Unauthorized scanning may be illegal in your jurisdiction.

---

**Built with ❤️ using FastAPI and Bootstrap 5**
