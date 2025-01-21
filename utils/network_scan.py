import os 
import sys
import ctypes
import subprocess
import shutil
import platform
import logging
import socket
import netifaces
import concurrent.futures
from datetime import datetime
from typing import Optional, List, Dict
from utils.network_scan import scan_network, analyze_traffic, check_bluetooth, check_wifi

banner = """
 _   _  _____ _____    _____ _
| \ | ||  ___/|_   _|  /  ___/ 
|  \| || |__   | |    \ `--. 
| . ` ||  __|  | |     `--. \ 
| |\  || |___  | |    /\__/ / 
\_| \_/\____/  \_/    \____/ 
"""

def is_admin():
    """Проверка прав администратора в Windows"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Перезапуск программы с правами администратора"""
    ctypes.windll.shell32.ShellExecuteW(
        None, 
        "runas",
        sys.executable,
        " ".join(sys.argv),
        None,
        1
    )

def setup_logging():
    """Настройка логирования"""
    logging.basicConfig(
        filename='network_scan.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

class NetworkScanner:
    def __init__(self):
        self.os_type = platform.system().lower()
        self._check_requirements()
        self.interface = self._get_default_interface()
        self.results_dir = self._create_results_dir()

    def _check_requirements(self) -> None:
        """Проверка наличия необходимых утилит"""
        required_tools = {
            'linux': ['nmap', 'tshark', 'rfkill', 'nmcli'],
            'windows': ['nmap', 'wireshark'],
            'darwin': ['nmap', 'tshark']
        }
        
        missing_tools = []
        for tool in required_tools.get(self.os_type, []):
            if not shutil.which(tool):
                missing_tools.append(tool)
        
        if missing_tools:
            raise RuntimeError(f"Отсутствуют необходимые утилиты: {', '.join(missing_tools)}")

    def _create_results_dir(self) -> str:
        """Создание директории для результатов"""
        dirname = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        os.makedirs(dirname, exist_ok=True)
        return dirname

    def _get_default_interface(self) -> str:
        """Улучшенное определение активного интерфейса"""
        try:
            if self.os_type == 'windows':
                # Получаем список активных интерфейсов в Windows
                interfaces = netifaces.interfaces()
                for iface in interfaces:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        return iface
            elif self.os_type == 'linux':
                result = self.run_command(['ip', 'route', 'get', '8.8.8.8'])
                return result.split()[result.split().index('dev') + 1]
        except Exception as e:
            logging.warning(f"Ошибка определения интерфейса: {e}")
        return 'eth0'

    def run_command(self, command: List[str]) -> str:
        """Выполнение системной команды с обработкой ошибок"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            error_msg = f"Ошибка при выполнении команды {' '.join(command)}: {e}"
            logging.error(error_msg)
            return error_msg
        except Exception as e:
            error_msg = f"Неожиданная ошибка: {str(e)}"
            logging.error(error_msg)
            return error_msg

    def scan_network(self, subnet: str = None) -> Dict[str, str]:
        """Расширенное сканирование сети"""
        if not subnet:
            # Автоопределение подсети
            ip = socket.gethostbyname(socket.gethostname())
            subnet = '.'.join(ip.split('.')[:-1]) + '.0/24'

        results = {}
        
        # Быстрое сканирование
        results['quick_scan'] = self.run_command(['nmap', '-sP', subnet])
        
        # Детальное сканирование
        results['detailed_scan'] = self.run_command(['nmap', '-sS', '-sV', subnet])
        
        # Сохранение результатов
        self._save_results('network_scan.txt', str(results))
        return results

    def analyze_traffic(self, duration: int = 30) -> Dict[str, str]:
        """Расширенный анализ трафика"""
        results = {}
        
        if self.os_type == 'windows':
            # Для Windows используем tshark
            results['packets'] = self.run_command([
                'tshark',
                '-i', self.interface,
                '-a', f'duration:{duration}',
                '-T', 'fields',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', 'tcp.port'
            ])
        else:
            # Для Linux используем tcpdump
            results['packets'] = self.run_command([
                'tcpdump',
                '-i', self.interface,
                '-n',
                '-c', '100'
            ])

        self._save_results('traffic_analysis.txt', str(results))
        return results

    def _save_results(self, filename: str, content: str) -> None:
        """Сохранение результатов в файл"""
        filepath = os.path.join(self.results_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)

    def check_bluetooth(self) -> str:
        """Проверка состояния Bluetooth"""
        print("Проверка наличия Bluetooth...")
        if self.os_type == 'linux':
            return self.run_command(['rfkill', 'list', 'bluetooth'])
        return "Проверка Bluetooth доступна только для Linux"

    def check_wifi(self) -> str:
        """Проверка состояния Wi-Fi"""
        print("Проверка наличия Wi-Fi...")
        if self.os_type == 'linux':
            return self.run_command(['nmcli', 'radio', 'wifi'])
        return "Проверка Wi-Fi доступна только для Linux"

    def scan_ports(self, target: str, ports: List[int]) -> Dict[int, bool]:
        """Сканирование портов"""
        results = {}
        
        def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            return port, result == 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_port, port) for port in ports]
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                results[port] = is_open

        return results

def main():
    print(banner)
    
    # Проверка и запрос прав администратора
    if not is_admin():
        print("Запрашиваем права администратора...")
        run_as_admin()
        sys.exit()

    setup_logging()
    print("Это приложение для обнаружения каналов утечки информации в локальной сети.")
    
    while True:
        confirmation = input("Вы уверены, что хотите продолжить? (да/нет): ").strip().lower()
        if confirmation in ['да', 'нет']:
            break
        print("Пожалуйста, введите 'да' или 'нет'")

    if confirmation == 'да':
        try:
            scanner = NetworkScanner()
            print("Начинаем сканирование сети...")
            results = {
                'network': scanner.scan_network(),
                'traffic': scanner.analyze_traffic(),
                'bluetooth': scanner.check_bluetooth(), 
                'wifi': scanner.check_wifi()
            }

            print("\nРезультаты анализа сети:")
            for key, value in results.items():
                print(f"\n{key.upper()}:")
                print(value)
                logging.info(f"{key}: {value}")

        except Exception as e:
            print(f"Произошла ошибка при сканировании: {str(e)}")
            logging.error(f"Ошибка сканирования: {str(e)}")
            input("Нажмите Enter для завершения...")
        finally:
            print("\nЗавершение работы программы...")
    else:
        print("Сканирование отменено.")
        logging.info("Сканирование отменено пользователем")
        input("Нажмите Enter для завершения...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nПрограмма прервана пользователем")
        logging.info("Программа прервана пользователем")
        input("Нажмите Enter для завершения...")
        sys.exit(0)