# Contributing to Metasploit-AI

Thank you for your interest in contributing to Metasploit-AI! This document provides guidelines and information for contributing to our AI-powered penetration testing framework.

## 🌟 Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md) to ensure a respectful and inclusive environment for all contributors.

## 🚀 Getting Started

### Prerequisites

- Python 3.8 or higher
- Git for version control
- Metasploit Framework installed
- Basic understanding of cybersecurity and penetration testing
- Familiarity with AI/ML concepts (for AI-related contributions)

### Development Environment Setup

1. **Fork the Repository**
   ```bash
   # Fork the repo on GitHub, then clone your fork
   git clone https://github.com/YOUR_USERNAME/metasploit-ai.git
   cd metasploit-ai
   ```

2. **Set Up Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

4. **Configure Development Environment**
   ```bash
   # Copy example configuration
   cp config/config.example.yaml config/config.yaml
   
   # Edit configuration for your environment
   nano config/config.yaml
   ```

5. **Run Tests**
   ```bash
   pytest tests/
   ```

## 📋 Types of Contributions

### 🔧 Code Contributions

#### AI/ML Components
- Vulnerability analysis algorithms
- Exploit recommendation systems
- Payload generation models
- Evasion technique implementations
- Model training and optimization

#### Core Framework
- Scanner modules and improvements
- Metasploit integration enhancements
- Database and session management
- Web interface features
- CLI improvements

#### Security Enhancements
- Authentication mechanisms
- Authorization controls
- Audit logging systems
- Encryption implementations
- Security vulnerability fixes

### 📚 Documentation
- API documentation
- User guides and tutorials
- Code comments and docstrings
- Architecture documentation
- Security best practices

### 🧪 Testing
- Unit tests for core functionality
- Integration tests for external services
- AI model validation tests
- Security testing and pen-testing
- Performance benchmarks

### 🐛 Bug Reports
- Detailed bug descriptions
- Reproduction steps
- System information
- Proposed solutions

## 🛠️ Development Workflow

### Branch Naming Convention

- `feature/short-description` - New features
- `bugfix/issue-number-description` - Bug fixes
- `security/vulnerability-description` - Security fixes
- `docs/documentation-update` - Documentation changes
- `ai/model-improvement` - AI/ML improvements

### Commit Message Format

```
type(scope): brief description

Optional longer description explaining the change in detail.

Closes #issue-number
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `security`: Security improvement
- `docs`: Documentation
- `style`: Code style/formatting
- `refactor`: Code refactoring
- `test`: Test additions/improvements
- `ai`: AI/ML related changes

**Examples:**
```
feat(ai): implement CVSS prediction model

Added machine learning model to predict CVSS scores based on 
vulnerability characteristics and historical data.

Closes #123
```

### Pull Request Process

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make Changes**
   - Write clean, well-documented code
   - Follow coding standards (PEP 8 for Python)
   - Add appropriate tests
   - Update documentation

3. **Test Your Changes**
   ```bash
   # Run all tests
   pytest tests/
   
   # Run specific test categories
   pytest tests/test_ai/
   pytest tests/test_core/
   
   # Check code coverage
   pytest --cov=src tests/
   
   # Run security checks
   bandit -r src/
   
   # Check code style
   flake8 src/
   black --check src/
   ```

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat(ai): your descriptive commit message"
   ```

5. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create Pull Request**
   - Use the pull request template
   - Provide clear description of changes
   - Link related issues
   - Include testing information
   - Add screenshots for UI changes

### Pull Request Template

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Security improvement
- [ ] Documentation update
- [ ] AI/ML enhancement

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] Security testing performed

## Checklist
- [ ] Code follows project style guidelines
- [ ] Self-review of code completed
- [ ] Code is commented, particularly in hard-to-understand areas
- [ ] Corresponding changes to documentation made
- [ ] Changes generate no new warnings
- [ ] Tests added that prove fix is effective or feature works
- [ ] New and existing unit tests pass locally

## Related Issues
Closes #(issue_number)

## Additional Notes
Any additional information, dependencies, or considerations.
```

## 🧪 Testing Guidelines

### Test Categories

1. **Unit Tests** (`tests/unit/`)
   - Test individual functions and classes
   - Mock external dependencies
   - Fast execution (< 1 second per test)

2. **Integration Tests** (`tests/integration/`)
   - Test component interactions
   - Use test databases and services
   - Moderate execution time (< 30 seconds per test)

3. **AI Model Tests** (`tests/ai/`)
   - Validate model accuracy and performance
   - Test training and inference pipelines
   - May have longer execution times

4. **Security Tests** (`tests/security/`)
   - Validate security controls
   - Test authentication and authorization
   - Penetration testing scenarios

### Writing Tests

```python
import pytest
from unittest.mock import Mock, patch
from src.core.scanner import NetworkScanner

class TestNetworkScanner:
    def test_scan_single_host(self):
        """Test scanning a single host."""
        scanner = NetworkScanner()
        result = scanner.scan_host("127.0.0.1", [80, 443])
        
        assert result is not None
        assert "127.0.0.1" in result
        
    @patch('src.core.scanner.nmap')
    def test_scan_with_mocked_nmap(self, mock_nmap):
        """Test scanning with mocked nmap."""
        mock_nmap.PortScanner.return_value.scan.return_value = {}
        
        scanner = NetworkScanner()
        result = scanner.scan_network("192.168.1.0/24")
        
        assert mock_nmap.PortScanner.called
        assert result is not None
```

## 🔒 Security Guidelines

### Secure Coding Practices

1. **Input Validation**
   - Validate all user inputs
   - Sanitize data before processing
   - Use parameterized queries for databases

2. **Authentication & Authorization**
   - Implement proper authentication mechanisms
   - Use role-based access control (RBAC)
   - Secure session management

3. **Encryption**
   - Encrypt sensitive data at rest and in transit
   - Use strong cryptographic algorithms
   - Secure key management

4. **Logging & Monitoring**
   - Log security-relevant events
   - Avoid logging sensitive information
   - Implement audit trails

### Security Review Process

All security-related changes must:
1. Be reviewed by security team members
2. Include security impact assessment
3. Pass security testing requirements
4. Include documentation updates

## 🤖 AI/ML Contribution Guidelines

### Model Development

1. **Data Requirements**
   - Use only publicly available vulnerability data
   - Ensure data privacy and compliance
   - Document data sources and licensing

2. **Model Training**
   - Use reproducible training pipelines
   - Implement proper validation techniques
   - Document model architecture and parameters

3. **Performance Metrics**
   - Include accuracy, precision, recall, F1-score
   - Measure inference time and resource usage
   - Compare against baseline models

4. **Ethical Considerations**
   - Avoid biased training data
   - Consider fairness and transparency
   - Document potential misuse scenarios

### AI Code Examples

```python
import tensorflow as tf
from sklearn.metrics import accuracy_score, classification_report

class VulnerabilityClassifier:
    """AI model for vulnerability classification."""
    
    def __init__(self, model_path=None):
        """Initialize the classifier."""
        self.model = None
        if model_path:
            self.load_model(model_path)
    
    def train(self, X_train, y_train, X_val, y_val):
        """Train the classification model."""
        # Model architecture
        self.model = tf.keras.Sequential([
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(len(np.unique(y_train)), activation='softmax')
        ])
        
        # Compile model
        self.model.compile(
            optimizer='adam',
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy']
        )
        
        # Train model
        history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=100,
            batch_size=32,
            verbose=1
        )
        
        return history
    
    def predict(self, X):
        """Make predictions on new data."""
        if self.model is None:
            raise ValueError("Model not trained or loaded")
        
        return self.model.predict(X)
```

## 📊 Performance Guidelines

### Optimization Requirements

1. **Response Time**
   - Web interface: < 2 seconds for most operations
   - CLI commands: < 5 seconds for complex operations
   - AI inference: < 1 second for single predictions

2. **Resource Usage**
   - Memory: Efficient memory management
   - CPU: Utilize multi-threading where appropriate
   - Disk: Implement caching for frequently accessed data

3. **Scalability**
   - Support concurrent users/operations
   - Implement connection pooling for databases
   - Use async programming patterns

### Performance Testing

```python
import time
import concurrent.futures
from src.core.framework import MetasploitAIFramework

def performance_test_concurrent_scans():
    """Test framework performance with concurrent scans."""
    framework = MetasploitAIFramework()
    
    def run_scan(target):
        start_time = time.time()
        result = framework.run_scan(target)
        end_time = time.time()
        return end_time - start_time
    
    targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(run_scan, targets))
    
    avg_time = sum(results) / len(results)
    assert avg_time < 30  # Should complete within 30 seconds
```

## 📝 Documentation Standards

### Code Documentation

1. **Docstrings**
   ```python
   def analyze_vulnerability(self, vuln_data: Dict[str, Any]) -> VulnAnalysis:
       """Analyze vulnerability using AI models.
       
       Args:
           vuln_data: Dictionary containing vulnerability information
               - cve_id: CVE identifier (str)
               - description: Vulnerability description (str)
               - cvss_score: CVSS score if available (float, optional)
               - affected_systems: List of affected systems (List[str])
       
       Returns:
           VulnAnalysis: Analysis results containing:
               - severity: Predicted severity level (str)
               - exploitability: Exploitability score (float)
               - recommendations: List of remediation recommendations (List[str])
       
       Raises:
           ValueError: If vuln_data is missing required fields
           ModelNotLoadedError: If AI models are not properly loaded
       
       Example:
           >>> analyzer = VulnerabilityAnalyzer()
           >>> vuln_data = {
           ...     'cve_id': 'CVE-2021-1234',
           ...     'description': 'Buffer overflow in service X',
           ...     'affected_systems': ['Windows 10', 'Windows Server 2019']
           ... }
           >>> analysis = analyzer.analyze_vulnerability(vuln_data)
           >>> print(analysis.severity)
           'HIGH'
       """
   ```

2. **Comments**
   - Explain complex algorithms and business logic
   - Document security considerations
   - Clarify AI model decisions

3. **Type Hints**
   ```python
   from typing import Dict, List, Optional, Union
   
   def predict_exploit_success(
       self, 
       target_info: Dict[str, str], 
       exploit_name: str,
       confidence_threshold: float = 0.8
   ) -> Optional[float]:
       """Predict exploit success probability."""
       pass
   ```

### API Documentation

Use OpenAPI/Swagger specifications for REST API documentation:

```yaml
paths:
  /api/v1/scan:
    post:
      summary: Start a new network scan
      description: Initiates a comprehensive network scan with AI-powered analysis
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                targets:
                  type: array
                  items:
                    type: string
                  description: List of target IP addresses or networks
                scan_type:
                  type: string
                  enum: [quick, comprehensive, stealth]
                  description: Type of scan to perform
      responses:
        200:
          description: Scan started successfully
          content:
            application/json:
              schema:
                type: object
                properties:
                  scan_id:
                    type: string
                    description: Unique identifier for the scan
```

## 🏆 Recognition

### Contributor Levels

1. **Contributor**: Made at least one merged pull request
2. **Regular Contributor**: 5+ merged pull requests
3. **Core Contributor**: 20+ merged pull requests + security/AI expertise
4. **Maintainer**: Trusted with repository maintenance and releases

### Recognition Program

- Contributors listed in `CONTRIBUTORS.md`
- Special recognition in release notes
- Annual contributor appreciation
- Conference speaking opportunities
- ZehraSec partnership opportunities

## 📧 Communication

### Channels

1. **GitHub Issues**: Bug reports and feature requests
2. **GitHub Discussions**: General questions and community discussions
3. **Email**: security@zehrasec.com for security issues
4. **WhatsApp**: [ZehraSec Business Channel](https://whatsapp.com/channel/0029Vaoa1GfKLaHlL0Kc8k1q)

### Communication Guidelines

- Be respectful and professional
- Provide clear and detailed information
- Search existing issues before creating new ones
- Use appropriate labels and templates
- Tag relevant maintainers when needed

## 🚨 Reporting Security Issues

Please do not report security vulnerabilities through public GitHub issues. Instead:

1. Email: security@zehrasec.com
2. Include detailed vulnerability information
3. Provide proof-of-concept if possible
4. Allow time for responsible disclosure

See our [Security Policy](SECURITY.md) for complete details.

## 📜 License

By contributing to Metasploit-AI, you agree that your contributions will be licensed under the Apache License 2.0.

## 🙏 Thank You

Thank you for contributing to Metasploit-AI! Your efforts help make cybersecurity tools more effective and accessible to the security community.

---

**Made with ❤️ by [Yashab Alam](https://github.com/yashab-cyber) and the [ZehraSec](https://www.zehrasec.com) Team**
