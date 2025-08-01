"""
Database Management Module
Handles data persistence for Metasploit-AI Framework
"""

import asyncio
import sqlite3
import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
from dataclasses import asdict

try:
    import aiosqlite
    AIOSQLITE_AVAILABLE = True
except ImportError:
    AIOSQLITE_AVAILABLE = False

from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Float, Boolean, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.dialects.sqlite import JSON

from ..utils.logger import get_logger

Base = declarative_base()

class ScanResult(Base):
    """Database model for scan results"""
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True)
    target = Column(String(255), nullable=False)
    scan_type = Column(String(50), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    vulnerabilities = Column(JSON)
    services = Column(JSON)
    os_info = Column(JSON)
    risk_score = Column(Float, default=0.0)
    raw_data = Column(Text)

class ExploitResult(Base):
    """Database model for exploit results"""
    __tablename__ = 'exploit_results'
    
    id = Column(Integer, primary_key=True)
    target = Column(String(255), nullable=False)
    exploit_name = Column(String(255), nullable=False)
    success = Column(Boolean, default=False)
    payload = Column(String(255))
    timestamp = Column(DateTime, default=datetime.utcnow)
    session_id = Column(String(100))
    details = Column(JSON)
    error_message = Column(Text)

class VulnerabilityData(Base):
    """Database model for vulnerability data"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    cve_id = Column(String(20), unique=True)
    description = Column(Text)
    severity = Column(String(20))
    cvss_score = Column(Float)
    published_date = Column(DateTime)
    references = Column(JSON)
    exploits = Column(JSON)
    
class Target(Base):
    """Database model for targets"""
    __tablename__ = 'targets'
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False)
    hostname = Column(String(255))
    os_name = Column(String(100))
    os_version = Column(String(50))
    last_scan = Column(DateTime)
    risk_level = Column(String(20))
    notes = Column(Text)
    tags = Column(JSON)

class Session(Base):
    """Database model for active sessions"""
    __tablename__ = 'sessions'
    
    id = Column(Integer, primary_key=True)
    session_id = Column(String(100), unique=True, nullable=False)
    target = Column(String(255), nullable=False)
    exploit_used = Column(String(255))
    payload_used = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    last_activity = Column(DateTime)
    status = Column(String(20), default='active')
    commands_executed = Column(JSON)

class AuditLog(Base):
    """Database model for audit logs"""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    user = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)
    target = Column(String(255))
    result = Column(String(20))
    details = Column(JSON)

class DatabaseManager:
    """Database management class"""
    
    def __init__(self, config):
        """Initialize database manager"""
        self.config = config
        self.logger = get_logger(__name__)
        self.engine = None
        self.session_maker = None
        self.async_pool = None
        
        # Database configuration
        self.db_type = config.type
        self.db_path = config.path
        self.db_host = getattr(config, 'host', 'localhost')
        self.db_port = getattr(config, 'port', 5432)
        self.db_name = getattr(config, 'database', 'metasploit_ai')
        self.db_user = getattr(config, 'username', '')
        self.db_password = getattr(config, 'password', '')
    
    async def initialize(self) -> bool:
        """Initialize database connection and create tables"""
        try:
            self.logger.info("🗄️ Initializing database...")
            
            # Create database URL
            if self.db_type == 'sqlite':
                # Ensure directory exists
                Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
                db_url = f"sqlite:///{self.db_path}"
            elif self.db_type == 'postgresql':
                db_url = f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"
            elif self.db_type == 'mysql':
                db_url = f"mysql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{self.db_name}"
            else:
                raise ValueError(f"Unsupported database type: {self.db_type}")
            
            # Create engine
            self.engine = create_engine(
                db_url,
                echo=False,
                pool_pre_ping=True,
                connect_args={'check_same_thread': False} if self.db_type == 'sqlite' else {}
            )
            
            # Create session maker
            self.session_maker = sessionmaker(bind=self.engine)
            
            # Create tables
            Base.metadata.create_all(self.engine)
            
            # Test connection
            with self.session_maker() as session:
                session.execute(text("SELECT 1"))
            
            self.logger.info("✅ Database initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Database initialization failed: {e}")
            return False
    
    async def store_scan_result(self, scan_result) -> int:
        """Store scan result in database"""
        try:
            with self.session_maker() as session:
                db_scan = ScanResult(
                    target=scan_result.target,
                    scan_type=getattr(scan_result, 'scan_type', 'unknown'),
                    timestamp=scan_result.timestamp,
                    vulnerabilities=scan_result.vulnerabilities,
                    services=scan_result.services,
                    os_info=scan_result.os_info,
                    risk_score=scan_result.risk_score,
                    raw_data=json.dumps(asdict(scan_result) if hasattr(scan_result, '__dict__') else str(scan_result))
                )
                
                session.add(db_scan)
                session.commit()
                
                scan_id = db_scan.id
                self.logger.info(f"📝 Stored scan result with ID: {scan_id}")
                return scan_id
                
        except Exception as e:
            self.logger.error(f"❌ Failed to store scan result: {e}")
            return -1
    
    async def store_exploit_result(self, exploit_result) -> int:
        """Store exploit result in database"""
        try:
            with self.session_maker() as session:
                db_exploit = ExploitResult(
                    target=exploit_result.target,
                    exploit_name=exploit_result.exploit_name,
                    success=exploit_result.success,
                    payload=exploit_result.payload,
                    timestamp=exploit_result.timestamp,
                    session_id=exploit_result.details.get('session', {}).get('id') if exploit_result.details else None,
                    details=exploit_result.details,
                    error_message=exploit_result.details.get('error') if not exploit_result.success else None
                )
                
                session.add(db_exploit)
                session.commit()
                
                exploit_id = db_exploit.id
                self.logger.info(f"📝 Stored exploit result with ID: {exploit_id}")
                return exploit_id
                
        except Exception as e:
            self.logger.error(f"❌ Failed to store exploit result: {e}")
            return -1
    
    async def store_session(self, session_info: Dict) -> int:
        """Store session information in database"""
        try:
            with self.session_maker() as session:
                db_session = Session(
                    session_id=session_info['id'],
                    target=session_info.get('target', ''),
                    exploit_used=session_info.get('exploit', ''),
                    payload_used=session_info.get('payload', ''),
                    created_at=datetime.now(),
                    last_activity=datetime.now(),
                    status='active',
                    commands_executed=[]
                )
                
                session.add(db_session)
                session.commit()
                
                session_db_id = db_session.id
                self.logger.info(f"📝 Stored session with ID: {session_db_id}")
                return session_db_id
                
        except Exception as e:
            self.logger.error(f"❌ Failed to store session: {e}")
            return -1
    
    async def update_session_activity(self, session_id: str, command: str):
        """Update session activity"""
        try:
            with self.session_maker() as session:
                db_session = session.query(Session).filter_by(session_id=session_id).first()
                if db_session:
                    db_session.last_activity = datetime.now()
                    
                    # Add command to history
                    if db_session.commands_executed is None:
                        db_session.commands_executed = []
                    
                    db_session.commands_executed.append({
                        'command': command,
                        'timestamp': datetime.now().isoformat()
                    })
                    
                    session.commit()
                    self.logger.debug(f"Updated session {session_id} activity")
                
        except Exception as e:
            self.logger.error(f"❌ Failed to update session activity: {e}")
    
    async def get_scan_history(self, target: str = None, limit: int = 100) -> List[Dict]:
        """Get scan history"""
        try:
            with self.session_maker() as session:
                query = session.query(ScanResult)
                
                if target:
                    query = query.filter(ScanResult.target == target)
                
                query = query.order_by(ScanResult.timestamp.desc()).limit(limit)
                results = query.all()
                
                history = []
                for result in results:
                    history.append({
                        'id': result.id,
                        'target': result.target,
                        'scan_type': result.scan_type,
                        'timestamp': result.timestamp,
                        'risk_score': result.risk_score,
                        'vulnerabilities_count': len(result.vulnerabilities) if result.vulnerabilities else 0,
                        'services_count': len(result.services) if result.services else 0
                    })
                
                return history
                
        except Exception as e:
            self.logger.error(f"❌ Failed to get scan history: {e}")
            return []
    
    async def get_exploit_history(self, target: str = None, limit: int = 100) -> List[Dict]:
        """Get exploit history"""
        try:
            with self.session_maker() as session:
                query = session.query(ExploitResult)
                
                if target:
                    query = query.filter(ExploitResult.target == target)
                
                query = query.order_by(ExploitResult.timestamp.desc()).limit(limit)
                results = query.all()
                
                history = []
                for result in results:
                    history.append({
                        'id': result.id,
                        'target': result.target,
                        'exploit_name': result.exploit_name,
                        'success': result.success,
                        'timestamp': result.timestamp,
                        'session_id': result.session_id,
                        'error_message': result.error_message
                    })
                
                return history
                
        except Exception as e:
            self.logger.error(f"❌ Failed to get exploit history: {e}")
            return []
    
    async def get_active_sessions(self) -> List[Dict]:
        """Get active sessions"""
        try:
            with self.session_maker() as session:
                results = session.query(Session).filter(Session.status == 'active').all()
                
                sessions = []
                for result in results:
                    sessions.append({
                        'id': result.id,
                        'session_id': result.session_id,
                        'target': result.target,
                        'exploit_used': result.exploit_used,
                        'created_at': result.created_at,
                        'last_activity': result.last_activity,
                        'commands_count': len(result.commands_executed) if result.commands_executed else 0
                    })
                
                return sessions
                
        except Exception as e:
            self.logger.error(f"❌ Failed to get active sessions: {e}")
            return []
    
    async def get_vulnerability_stats(self) -> Dict:
        """Get vulnerability statistics"""
        try:
            with self.session_maker() as session:
                # Get total scans
                total_scans = session.query(ScanResult).count()
                
                # Get scans in last 24 hours
                recent_scans = session.query(ScanResult).filter(
                    ScanResult.timestamp >= datetime.now() - timedelta(days=1)
                ).count()
                
                # Get vulnerability severity distribution
                severity_stats = {}
                scan_results = session.query(ScanResult).all()
                
                for scan in scan_results:
                    if scan.vulnerabilities:
                        for vuln in scan.vulnerabilities:
                            severity = vuln.get('severity', 'Unknown')
                            severity_stats[severity] = severity_stats.get(severity, 0) + 1
                
                # Get top vulnerable targets
                target_risk = {}
                for scan in scan_results:
                    target = scan.target
                    risk_score = scan.risk_score or 0
                    
                    if target not in target_risk or target_risk[target] < risk_score:
                        target_risk[target] = risk_score
                
                top_targets = sorted(target_risk.items(), key=lambda x: x[1], reverse=True)[:10]
                
                return {
                    'total_scans': total_scans,
                    'recent_scans': recent_scans,
                    'severity_distribution': severity_stats,
                    'top_vulnerable_targets': top_targets
                }
                
        except Exception as e:
            self.logger.error(f"❌ Failed to get vulnerability stats: {e}")
            return {}
    
    async def log_audit_event(self, user: str, action: str, target: str = None, 
                            result: str = 'success', details: Dict = None):
        """Log audit event"""
        try:
            with self.session_maker() as session:
                audit_log = AuditLog(
                    user=user,
                    action=action,
                    target=target,
                    result=result,
                    details=details or {}
                )
                
                session.add(audit_log)
                session.commit()
                
                self.logger.debug(f"Logged audit event: {action} by {user}")
                
        except Exception as e:
            self.logger.error(f"❌ Failed to log audit event: {e}")
    
    async def search_scan_results(self, query: str, filters: Dict = None) -> List[Dict]:
        """Search scan results"""
        try:
            with self.session_maker() as session:
                db_query = session.query(ScanResult)
                
                # Apply text search
                if query:
                    db_query = db_query.filter(
                        ScanResult.target.contains(query) |
                        ScanResult.raw_data.contains(query)
                    )
                
                # Apply filters
                if filters:
                    if 'start_date' in filters:
                        db_query = db_query.filter(ScanResult.timestamp >= filters['start_date'])
                    
                    if 'end_date' in filters:
                        db_query = db_query.filter(ScanResult.timestamp <= filters['end_date'])
                    
                    if 'min_risk_score' in filters:
                        db_query = db_query.filter(ScanResult.risk_score >= filters['min_risk_score'])
                
                results = db_query.order_by(ScanResult.timestamp.desc()).limit(100).all()
                
                search_results = []
                for result in results:
                    search_results.append({
                        'id': result.id,
                        'target': result.target,
                        'timestamp': result.timestamp,
                        'risk_score': result.risk_score,
                        'vulnerabilities': result.vulnerabilities,
                        'services': result.services
                    })
                
                return search_results
                
        except Exception as e:
            self.logger.error(f"❌ Search failed: {e}")
            return []
    
    async def backup_database(self, backup_path: str) -> bool:
        """Create database backup"""
        try:
            if self.db_type == 'sqlite':
                # SQLite backup
                import shutil
                shutil.copy2(self.db_path, backup_path)
                self.logger.info(f"📦 Database backed up to {backup_path}")
                return True
            else:
                # For other databases, would need specific backup procedures
                self.logger.warning("⚠️ Database backup not implemented for this database type")
                return False
                
        except Exception as e:
            self.logger.error(f"❌ Database backup failed: {e}")
            return False
    
    async def optimize_database(self):
        """Optimize database performance"""
        try:
            with self.session_maker() as session:
                if self.db_type == 'sqlite':
                    session.execute("VACUUM")
                    session.execute("ANALYZE")
                
                session.commit()
                self.logger.info("🔧 Database optimized")
                
        except Exception as e:
            self.logger.error(f"❌ Database optimization failed: {e}")
    
    async def cleanup_old_data(self, days_to_keep: int = 90):
        """Clean up old data from database"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            
            with self.session_maker() as session:
                # Clean old scan results
                old_scans = session.query(ScanResult).filter(
                    ScanResult.timestamp < cutoff_date
                ).delete()
                
                # Clean old exploit results
                old_exploits = session.query(ExploitResult).filter(
                    ExploitResult.timestamp < cutoff_date
                ).delete()
                
                # Clean old audit logs
                old_audits = session.query(AuditLog).filter(
                    AuditLog.timestamp < cutoff_date
                ).delete()
                
                session.commit()
                
                self.logger.info(f"🧹 Cleaned up old data: {old_scans} scans, {old_exploits} exploits, {old_audits} audit logs")
                
        except Exception as e:
            self.logger.error(f"❌ Data cleanup failed: {e}")
    
    async def close(self):
        """Close database connections"""
        try:
            if self.engine:
                self.engine.dispose()
            
            self.logger.info("🔌 Database connections closed")
            
        except Exception as e:
            self.logger.error(f"❌ Error closing database: {e}")
    
    def get_connection_info(self) -> Dict:
        """Get database connection information"""
        return {
            'type': self.db_type,
            'path': self.db_path if self.db_type == 'sqlite' else None,
            'host': self.db_host if self.db_type != 'sqlite' else None,
            'port': self.db_port if self.db_type != 'sqlite' else None,
            'database': self.db_name if self.db_type != 'sqlite' else None,
            'connected': self.engine is not None
        }
