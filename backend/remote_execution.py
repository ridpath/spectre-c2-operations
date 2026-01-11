import paramiko
import winrm
from typing import Dict, Any, Optional
from dataclasses import dataclass
from enum import Enum


class ExecutionProtocol(str, Enum):
    SSH = "ssh"
    WINRM = "winrm"
    LOCAL = "local"


@dataclass
class ExecutionTarget:
    host: str
    port: int
    username: str
    password: Optional[str] = None
    key_file: Optional[str] = None
    protocol: ExecutionProtocol = ExecutionProtocol.SSH


@dataclass
class ExecutionResult:
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float


class SSHExecutor:
    def __init__(self, target: ExecutionTarget):
        self.target = target
        self.client: Optional[paramiko.SSHClient] = None
        
    def connect(self) -> bool:
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if self.target.key_file:
                self.client.connect(
                    hostname=self.target.host,
                    port=self.target.port,
                    username=self.target.username,
                    key_filename=self.target.key_file,
                    timeout=10
                )
            elif self.target.password:
                self.client.connect(
                    hostname=self.target.host,
                    port=self.target.port,
                    username=self.target.username,
                    password=self.target.password,
                    timeout=10
                )
            else:
                return False
            
            return True
            
        except Exception as e:
            print(f"SSH connection failed: {e}")
            return False
    
    def execute(self, command: str, timeout: int = 30) -> ExecutionResult:
        if not self.client:
            if not self.connect():
                return ExecutionResult(
                    success=False,
                    stdout="",
                    stderr="Failed to connect to SSH server",
                    exit_code=-1,
                    execution_time=0.0
                )
        
        try:
            import time
            start_time = time.time()
            
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)
            
            exit_code = stdout.channel.recv_exit_status()
            stdout_data = stdout.read().decode('utf-8', errors='ignore')
            stderr_data = stderr.read().decode('utf-8', errors='ignore')
            
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                success=exit_code == 0,
                stdout=stdout_data,
                stderr=stderr_data,
                exit_code=exit_code,
                execution_time=execution_time
            )
            
        except Exception as e:
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=f"Execution error: {str(e)}",
                exit_code=-1,
                execution_time=0.0
            )
    
    def disconnect(self):
        if self.client:
            self.client.close()
            self.client = None


class WinRMExecutor:
    def __init__(self, target: ExecutionTarget):
        self.target = target
        self.session: Optional[winrm.Session] = None
        
    def connect(self) -> bool:
        try:
            endpoint = f"http://{self.target.host}:{self.target.port}/wsman"
            
            self.session = winrm.Session(
                endpoint,
                auth=(self.target.username, self.target.password),
                transport='ntlm'
            )
            
            result = self.session.run_cmd('echo test')
            return result.status_code == 0
            
        except Exception as e:
            print(f"WinRM connection failed: {e}")
            return False
    
    def execute(self, command: str, timeout: int = 30) -> ExecutionResult:
        if not self.session:
            if not self.connect():
                return ExecutionResult(
                    success=False,
                    stdout="",
                    stderr="Failed to connect to WinRM server",
                    exit_code=-1,
                    execution_time=0.0
                )
        
        try:
            import time
            start_time = time.time()
            
            if command.startswith('powershell'):
                result = self.session.run_ps(command.replace('powershell ', ''))
            else:
                result = self.session.run_cmd(command)
            
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                success=result.status_code == 0,
                stdout=result.std_out.decode('utf-8', errors='ignore'),
                stderr=result.std_err.decode('utf-8', errors='ignore'),
                exit_code=result.status_code,
                execution_time=execution_time
            )
            
        except Exception as e:
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=f"Execution error: {str(e)}",
                exit_code=-1,
                execution_time=0.0
            )
    
    def disconnect(self):
        self.session = None


class RemoteExecutionManager:
    def __init__(self):
        self.executors: Dict[str, Any] = {}
        
    def create_executor(self, target: ExecutionTarget) -> Any:
        executor_key = f"{target.protocol}_{target.host}_{target.port}"
        
        if executor_key in self.executors:
            return self.executors[executor_key]
        
        if target.protocol == ExecutionProtocol.SSH:
            executor = SSHExecutor(target)
        elif target.protocol == ExecutionProtocol.WINRM:
            executor = WinRMExecutor(target)
        else:
            raise ValueError(f"Unsupported protocol: {target.protocol}")
        
        self.executors[executor_key] = executor
        return executor
    
    def execute_command(
        self,
        command: str,
        target: ExecutionTarget,
        timeout: int = 30
    ) -> ExecutionResult:
        executor = self.create_executor(target)
        return executor.execute(command, timeout)
    
    def execute_local(self, command: str, timeout: int = 30) -> ExecutionResult:
        import subprocess
        import time
        
        try:
            start_time = time.time()
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            execution_time = time.time() - start_time
            
            return ExecutionResult(
                success=result.returncode == 0,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                execution_time=execution_time
            )
            
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                exit_code=-1,
                execution_time=timeout
            )
        except Exception as e:
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=f"Execution error: {str(e)}",
                exit_code=-1,
                execution_time=0.0
            )
    
    def close_all(self):
        for executor in self.executors.values():
            try:
                executor.disconnect()
            except:
                pass
        self.executors.clear()


remote_executor = RemoteExecutionManager()
