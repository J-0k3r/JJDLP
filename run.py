#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DLP数据泄露防护系统启动脚本
"""

import os
import sys
import subprocess
import argparse
import platform
import time
import requests
from pathlib import Path

LOCK_FILE = Path("installed.lock")

def check_lock_file():
    """检查锁文件"""
    if LOCK_FILE.exists():
        print("依赖包已安装，跳过安装步骤")
        return True
    return False

def check_python_version():
    """检查Python版本"""
    if sys.version_info < (3, 8):
        print("错误：需要Python 3.8或更高版本")
        sys.exit(1)
    print(f"Python版本检查通过：{sys.version}")

def install_dependencies():
    """安装依赖包"""
    print("正在安装依赖包...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("依赖包安装完成")
    except subprocess.CalledProcessError as e:
        print(f"依赖包安装失败：{e}")
        sys.exit(1)

def create_directories():
    """创建必要的目录"""
    directories = [
        "uploads",
        "logs"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"创建目录：{directory}")


def download_static():
    """下载静态文件"""
    print("正在下载静态文件...")
    try:
        subprocess.check_call([sys.executable, "routes/fetch_assets.py"])
    except subprocess.CalledProcessError as e:
        print(f"静态文件下载失败：{e}")
        sys.exit(1)
    print("静态文件下载完成")


def init_database():
    """初始化数据库"""
    print("正在初始化数据库...")
    try:
        from app import app, db
        with app.app_context():
            db.create_all()
        print("数据库初始化完成")
    except Exception as e:
        print(f"数据库初始化失败：{e}")
        sys.exit(1)

def start_idcard_ocr_service():
    """启动idcard_ocr服务（根据操作系统使用不同方式）"""
    print("正在启动idcard_ocr服务...")
    
    # 检查idcard_ocr目录是否存在
    idcard_ocr_path = Path("idcard_ocr")
    if not idcard_ocr_path.exists():
        print("警告: idcard_ocr目录不存在，跳过启动")
        return (None, None)
    
    app_py = idcard_ocr_path / "app.py"
    if not app_py.exists():
        print("警告: idcard_ocr/app.py不存在，跳过启动")
        return (None, None)
    
    # 检查服务是否已经在运行
    try:
        response = requests.get("http://localhost:8088/health", timeout=2)
        if response.status_code == 200:
            print("idcard_ocr服务已在运行")
            return (None, None)  # 返回 (None, None) 表示服务已存在，不是我们启动的
    except:
        pass  # 服务未运行，继续启动
    
    # 根据操作系统选择启动方式
    system = platform.system()
    idcard_ocr_dir = str(idcard_ocr_path.absolute())
    
    try:
        # 创建日志文件目录
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        stdout_log = log_dir / "idcard_ocr_stdout.log"
        stderr_log = log_dir / "idcard_ocr_stderr.log"
        
        # 打开日志文件（追加模式，保持打开）
        stdout_file = open(stdout_log, 'a', encoding='utf-8')
        stderr_file = open(stderr_log, 'a', encoding='utf-8')
        
        if system == "Windows":
            # Windows: 直接使用Popen，但确保进程独立运行
            # 不使用CREATE_NO_WINDOW，让Flask正常输出到日志文件
            process = subprocess.Popen(
                [sys.executable, "app.py"],
                cwd=idcard_ocr_dir,
                stdout=stdout_file,
                stderr=stderr_file,
                # 不使用creationflags，让进程正常启动
            )
        else:
            # Linux/Unix: 使用start_new_session在后台运行，输出重定向到文件
            process = subprocess.Popen(
                [sys.executable, "app.py"],
                cwd=idcard_ocr_dir,
                stdout=stdout_file,
                stderr=stderr_file,
                start_new_session=True
            )
        
        # 注意：不关闭文件，让进程持续写入日志
        # 文件会在进程结束时自动关闭
        
        # 等待几秒检查服务是否启动成功
        print("等待idcard_ocr服务启动...")
        for i in range(15):  # 增加到15秒，给模型加载更多时间
            time.sleep(1)
            # 检查进程是否还在运行
            if process.poll() is not None:
                # 进程已退出，读取错误日志
                print(f"警告: idcard_ocr进程已退出，退出码: {process.returncode}")
                try:
                    stderr_file.flush()
                    with open(stderr_log, 'r', encoding='utf-8') as f:
                        error_content = f.read()
                        if error_content:
                            print(f"错误日志: {error_content[-500:]}")  # 显示最后500字符
                except:
                    pass
                break
            
            # 检查服务是否响应
            try:
                response = requests.get("http://localhost:8088/health", timeout=1)
                if response.status_code == 200:
                    print("idcard_ocr服务启动成功")
                    return (process, (stdout_file, stderr_file))
            except:
                continue
        
        # 检查最终状态
        if process.poll() is None:
            print("警告: idcard_ocr服务启动超时，但进程仍在运行")
            print(f"提示: 请查看日志文件 {stdout_log} 和 {stderr_log} 了解详情")
            return (process, (stdout_file, stderr_file))
        else:
            print(f"错误: idcard_ocr进程启动失败，退出码: {process.returncode}")
            print(f"提示: 请查看日志文件 {stderr_log} 了解错误详情")
            return (None, None)
        
    except Exception as e:
        print(f"启动idcard_ocr服务失败：{e}")
        print("系统将继续运行，但图片识别功能可能不可用")
        # 关闭已打开的文件（如果已打开）
        try:
            if 'stdout_file' in locals():
                stdout_file.close()
            if 'stderr_file' in locals():
                stderr_file.close()
        except:
            pass
        return (None, None)

def start_server(host="0.0.0.0", port=5000, debug=False):
    """启动服务器"""
    print(f"正在启动DLP系统...")
    print(f"访问地址：http://{host}:{port}")
    print("按 Ctrl+C 停止服务")
    
    try:
        from app import app
        app.run(host=host, port=port, debug=debug)
    except KeyboardInterrupt:
        print("\n服务已停止")
    except Exception as e:
        print(f"启动失败：{e}")
        sys.exit(1)

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="DLP数据泄露防护系统")
    parser.add_argument("--host", default="0.0.0.0", help="服务器地址 (默认: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="服务器端口 (默认: 5000)")
    parser.add_argument("--debug", action="store_true", help="启用调试模式")
    parser.add_argument("--install", action="store_true", help="仅安装依赖包")
    parser.add_argument("--init", action="store_true", help="仅初始化数据库")
    
    args = parser.parse_args()
    
    print("=" * 50)
    print("DLP数据泄露防护系统")
    print("=" * 50)
    
    if not check_lock_file():
    # 检查Python版本
       check_python_version()
       download_static()
       install_dependencies()
       create_directories()
       init_database()
       LOCK_FILE.touch()
       print("依赖包已安装，数据库已初始化")
       return


    # 安装依赖包
    if args.install:
        install_dependencies()
    
    
    # 初始化数据库
    if args.init :
        init_database()
    
    # 启动idcard_ocr服务（在启动主服务器之前）
    idcard_ocr_result = start_idcard_ocr_service()
    idcard_ocr_process = idcard_ocr_result[0] if isinstance(idcard_ocr_result, tuple) else idcard_ocr_result
    idcard_ocr_files = idcard_ocr_result[1] if isinstance(idcard_ocr_result, tuple) else None
    
    # 启动服务器
    try:
        start_server(args.host, args.port, args.debug)
    finally:
        # 如果idcard_ocr进程是我们启动的，尝试终止它
        if idcard_ocr_process:
            try:
                idcard_ocr_process.terminate()
                idcard_ocr_process.wait(timeout=5)
            except:
                try:
                    idcard_ocr_process.kill()
                except:
                    pass
            print("idcard_ocr服务已停止")
        
        # 关闭日志文件
        if idcard_ocr_files:
            try:
                idcard_ocr_files[0].close()  # stdout
                idcard_ocr_files[1].close()  # stderr
            except:
                pass

if __name__ == "__main__":
    main()
