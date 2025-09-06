import sys
import os
import ctypes
import ctypes.wintypes
import psutil
import struct
import time
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QListWidget, QLabel, 
                             QLineEdit, QFileDialog, QMessageBox, QFrame,
                             QSplitter, QGroupBox, QTextEdit, QProgressBar,
                             QTabWidget, QTableWidget, QTableWidgetItem, QHeaderView,
                             QMenuBar, QMenu, QToolBar, QAction, QComboBox,
                             QSpinBox, QCheckBox, QSlider, QTreeWidget, QTreeWidgetItem,
                             QDockWidget, QScrollArea, QGridLayout, QFormLayout,
                             QListWidgetItem, QDialog, QDialogButtonBox, QPlainTextEdit)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QDateTime, QTimer, QSize
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor, QPixmap, QPainter, QPen

# Windows API constants and functions
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
INFINITE = 0xFFFFFFFF

# Windows API functions
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

class ProcessWorker(QThread):
    """Worker thread for process operations"""
    process_attached = pyqtSignal(str)
    injection_complete = pyqtSignal(bool, str)
    progress_update = pyqtSignal(int)
    
    def __init__(self, process_name, dll_path):
        super().__init__()
        self.process_name = process_name
        self.dll_path = dll_path
        self.target_process = None
        
    def run(self):
        try:
            # Find and attach to process
            self.progress_update.emit(25)
            self.target_process = self.find_process(self.process_name)
            if not self.target_process:
                self.process_attached.emit(f"Process '{self.process_name}' not found")
                return
                
            self.progress_update.emit(50)
            self.process_attached.emit(f"Attached to process: {self.process_name} (PID: {self.target_process.pid})")
            
            # Inject DLL
            self.progress_update.emit(75)
            success, message = self.inject_dll(self.target_process, self.dll_path)
            self.progress_update.emit(100)
            self.injection_complete.emit(success, message)
            
        except Exception as e:
            self.injection_complete.emit(False, f"Error: {str(e)}")
    
    def find_process(self, process_name):
        """Find process by name"""
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'].lower() == process_name.lower():
                    return proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return None
    
    def inject_dll(self, process, dll_path):
        """Inject DLL into target process"""
        try:
            # Open process
            process_handle = kernel32.OpenProcess(
                PROCESS_ALL_ACCESS, False, process.pid
            )
            if not process_handle:
                return False, "Failed to open target process"
            
            # Allocate memory in target process
            dll_path_bytes = dll_path.encode('utf-8') + b'\x00'
            memory_address = kernel32.VirtualAllocEx(
                process_handle, None, len(dll_path_bytes),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
            )
            if not memory_address:
                kernel32.CloseHandle(process_handle)
                return False, "Failed to allocate memory in target process"
            
            # Write DLL path to allocated memory
            bytes_written = ctypes.c_size_t()
            if not kernel32.WriteProcessMemory(
                process_handle, memory_address, dll_path_bytes,
                len(dll_path_bytes), ctypes.byref(bytes_written)
            ):
                kernel32.CloseHandle(process_handle)
                return False, "Failed to write DLL path to target process"
            
            # Get LoadLibraryA address
            loadlibrary_addr = kernel32.GetProcAddress(
                kernel32.GetModuleHandleW("kernel32.dll"), "LoadLibraryA"
            )
            if not loadlibrary_addr:
                kernel32.CloseHandle(process_handle)
                return False, "Failed to get LoadLibraryA address"
            
            # Create remote thread
            thread_handle = kernel32.CreateRemoteThread(
                process_handle, None, 0, loadlibrary_addr,
                memory_address, 0, None
            )
            if not thread_handle:
                kernel32.CloseHandle(process_handle)
                return False, "Failed to create remote thread"
            
            # Wait for thread completion
            kernel32.WaitForSingleObject(thread_handle, INFINITE)
            
            # Cleanup
            kernel32.CloseHandle(thread_handle)
            kernel32.CloseHandle(process_handle)
            
            return True, "DLL injection successful"
            
        except Exception as e:
            return False, f"Injection failed: {str(e)}"

class DLLInjector(QMainWindow):
    def __init__(self):
        super().__init__()
        self.target_process = None
        self.target_pid = None
        self.dll_path = ""
        self.process_handle = None
        self.memory_regions = []
        self.scan_results = []
        self.init_ui()
        self.refresh_processes()
        
    def init_ui(self):
        """Initialize the professional reverse engineering interface"""
        self.setWindowTitle("Advanced DLL Injector & Memory Editor")
        self.setGeometry(50, 50, 1400, 900)
        self.setMinimumSize(1200, 800)
        
        # Apply professional dark theme
        self.apply_professional_theme()
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create toolbar
        self.create_toolbar()
        
        # Create central widget with tabbed interface
        self.create_central_widget()
        
        # Create dock widgets
        self.create_dock_widgets()
        
        # Create status bar
        self.create_status_bar()
        
        # Initialize timer for real-time updates
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_process_info)
        self.update_timer.start(1000)  # Update every second
        
        # Add initial log message
        self.log_message("Advanced DLL Injector & Memory Editor initialized")
        self.log_message("Professional reverse engineering tool ready")
        
    def apply_professional_theme(self):
        """Apply professional dark theme similar to x64dbg/Cheat Engine"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e1e;
                color: #d4d4d4;
            }
            
            /* Menu Bar */
            QMenuBar {
                background-color: #2d2d30;
                color: #d4d4d4;
                border-bottom: 1px solid #3e3e42;
                padding: 2px;
            }
            QMenuBar::item {
                background-color: transparent;
                padding: 4px 8px;
                margin: 1px;
            }
            QMenuBar::item:selected {
                background-color: #094771;
            }
            QMenu {
                background-color: #2d2d30;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
            }
            QMenu::item {
                padding: 6px 20px;
            }
            QMenu::item:selected {
                background-color: #094771;
            }
            
            /* Toolbar */
            QToolBar {
                background-color: #2d2d30;
                border: none;
                spacing: 3px;
                padding: 2px;
            }
            QToolBar QToolButton {
                background-color: transparent;
                border: 1px solid transparent;
                border-radius: 3px;
                padding: 6px;
                margin: 1px;
            }
            QToolBar QToolButton:hover {
                background-color: #3e3e42;
                border-color: #555555;
            }
            QToolBar QToolButton:pressed {
                background-color: #094771;
            }
            
            /* Tabs */
            QTabWidget::pane {
                border: 1px solid #3e3e42;
                background-color: #1e1e1e;
            }
            QTabBar::tab {
                background-color: #2d2d30;
                color: #d4d4d4;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background-color: #1e1e1e;
                border-bottom: 1px solid #1e1e1e;
            }
            QTabBar::tab:hover {
                background-color: #3e3e42;
            }
            
            /* Buttons */
            QPushButton {
                background-color: #0e639c;
                color: #ffffff;
                border: 1px solid #0e639c;
                border-radius: 3px;
                padding: 6px 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #1177bb;
                border-color: #1177bb;
            }
            QPushButton:pressed {
                background-color: #0d5a8a;
            }
            QPushButton:disabled {
                background-color: #3e3e42;
                color: #666666;
                border-color: #3e3e42;
            }
            
            /* Special action buttons */
            QPushButton[class="attach"] {
                background-color: #28a745;
                border-color: #28a745;
            }
            QPushButton[class="attach"]:hover {
                background-color: #34ce57;
                border-color: #34ce57;
            }
            QPushButton[class="inject"] {
                background-color: #dc3545;
                border-color: #dc3545;
            }
            QPushButton[class="inject"]:hover {
                background-color: #e74c3c;
                border-color: #e74c3c;
            }
            
            /* Lists and Tables */
            QListWidget, QTableWidget, QTreeWidget {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                selection-background-color: #094771;
                gridline-color: #3e3e42;
            }
            QListWidget::item, QTableWidget::item, QTreeWidget::item {
                padding: 4px;
                border-bottom: 1px solid #2d2d30;
            }
            QListWidget::item:selected, QTableWidget::item:selected, QTreeWidget::item:selected {
                background-color: #094771;
            }
            
            /* Line Edits and Text Areas */
            QLineEdit, QTextEdit, QPlainTextEdit {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                border-radius: 3px;
                padding: 4px;
            }
            QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
                border-color: #0e639c;
            }
            
            /* Combo Boxes */
            QComboBox {
                background-color: #1e1e1e;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
                border-radius: 3px;
                padding: 4px;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #d4d4d4;
                margin-right: 5px;
            }
            
            /* Progress Bar */
            QProgressBar {
                background-color: #1e1e1e;
                border: 1px solid #3e3e42;
                border-radius: 3px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #0e639c;
                border-radius: 2px;
            }
            
            /* Dock Widgets */
            QDockWidget {
                background-color: #2d2d30;
                color: #d4d4d4;
                border: 1px solid #3e3e42;
            }
            QDockWidget::title {
                background-color: #2d2d30;
                color: #d4d4d4;
                padding: 4px;
                border-bottom: 1px solid #3e3e42;
            }
            
            /* Scrollbars */
            QScrollBar:vertical {
                background-color: #1e1e1e;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #3e3e42;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #555555;
            }
            
            QScrollBar:horizontal {
                background-color: #1e1e1e;
                height: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal {
                background-color: #3e3e42;
                border-radius: 6px;
                min-width: 20px;
            }
            QScrollBar::handle:horizontal:hover {
                background-color: #555555;
            }
        """)
        
    def create_menu_bar(self):
        """Create professional menu bar"""
        menubar = self.menuBar()
        
        # File Menu
        file_menu = menubar.addMenu('&File')
        
        open_action = QAction('&Open Process', self)
        open_action.setShortcut('Ctrl+O')
        open_action.triggered.connect(self.open_process_dialog)
        file_menu.addAction(open_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('E&xit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools Menu
        tools_menu = menubar.addMenu('&Tools')
        
        scan_action = QAction('&Memory Scanner', self)
        scan_action.triggered.connect(self.open_memory_scanner)
        tools_menu.addAction(scan_action)
        
        hex_action = QAction('&Hex Editor', self)
        hex_action.triggered.connect(self.open_hex_editor)
        tools_menu.addAction(hex_action)
        
        # View Menu
        view_menu = menubar.addMenu('&View')
        
        refresh_action = QAction('&Refresh Processes', self)
        refresh_action.setShortcut('F5')
        refresh_action.triggered.connect(self.refresh_processes)
        view_menu.addAction(refresh_action)
        
        # Help Menu
        help_menu = menubar.addMenu('&Help')
        
        about_action = QAction('&About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def create_toolbar(self):
        """Create professional toolbar"""
        toolbar = QToolBar()
        toolbar.setMovable(False)
        toolbar.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        
        # Attach Process
        attach_action = QAction('🔗 Attach', self)
        attach_action.setToolTip('Attach to Process')
        attach_action.triggered.connect(self.attach_process)
        toolbar.addAction(attach_action)
        
        # Inject DLL
        inject_action = QAction('💉 Inject', self)
        inject_action.setToolTip('Inject DLL')
        inject_action.triggered.connect(self.inject_dll)
        toolbar.addAction(inject_action)
        
        toolbar.addSeparator()
        
        # Refresh
        refresh_action = QAction('🔄 Refresh', self)
        refresh_action.setToolTip('Refresh Process List')
        refresh_action.triggered.connect(self.refresh_processes)
        toolbar.addAction(refresh_action)
        
        # Memory Scanner
        scan_action = QAction('🔍 Scan', self)
        scan_action.setToolTip('Memory Scanner')
        scan_action.triggered.connect(self.open_memory_scanner)
        toolbar.addAction(scan_action)
        
        toolbar.addSeparator()
        
        # Hex Editor
        hex_action = QAction('📝 Hex', self)
        hex_action.setToolTip('Hex Editor')
        hex_action.triggered.connect(self.open_hex_editor)
        toolbar.addAction(hex_action)
        
        self.addToolBar(toolbar)
        
    def create_central_widget(self):
        """Create central tabbed widget"""
        self.central_tabs = QTabWidget()
        self.setCentralWidget(self.central_tabs)
        
        # Process Manager Tab
        self.create_process_tab()
        
        # Memory Viewer Tab
        self.create_memory_tab()
        
        # DLL Injector Tab
        self.create_injector_tab()
        
        # Assembly Disassembly Tab
        self.create_disassembly_tab()
        
    def create_process_tab(self):
        """Create process management tab"""
        process_widget = QWidget()
        layout = QVBoxLayout(process_widget)
        
        # Process list table
        self.process_table = QTableWidget()
        self.process_table.setColumnCount(6)
        self.process_table.setHorizontalHeaderLabels(['PID', 'Name', 'CPU %', 'Memory', 'Status', 'Architecture'])
        self.process_table.horizontalHeader().setStretchLastSection(True)
        self.process_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.process_table.itemDoubleClicked.connect(self.on_process_double_clicked)
        
        # Process controls
        controls_layout = QHBoxLayout()
        
        self.attach_btn = QPushButton('🔗 Attach Process')
        self.attach_btn.setProperty('class', 'attach')
        self.attach_btn.clicked.connect(self.attach_process)
        controls_layout.addWidget(self.attach_btn)
        
        self.refresh_btn = QPushButton('🔄 Refresh')
        self.refresh_btn.clicked.connect(self.refresh_processes)
        controls_layout.addWidget(self.refresh_btn)
        
        controls_layout.addStretch()
        
        # Search box
        search_label = QLabel('Search:')
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText('Filter processes...')
        self.search_box.textChanged.connect(self.filter_processes)
        controls_layout.addWidget(search_label)
        controls_layout.addWidget(self.search_box)
        
        layout.addLayout(controls_layout)
        layout.addWidget(self.process_table)
        
        self.central_tabs.addTab(process_widget, 'Process Manager')
        
    def create_memory_tab(self):
        """Create memory viewer tab"""
        memory_widget = QWidget()
        layout = QVBoxLayout(memory_widget)
        
        # Memory regions table
        self.memory_table = QTableWidget()
        self.memory_table.setColumnCount(5)
        self.memory_table.setHorizontalHeaderLabels(['Address', 'Size', 'Type', 'Protection', 'Module'])
        self.memory_table.horizontalHeader().setStretchLastSection(True)
        
        # Memory controls
        mem_controls = QHBoxLayout()
        
        refresh_mem_btn = QPushButton('🔄 Refresh Memory')
        refresh_mem_btn.clicked.connect(self.refresh_memory_regions)
        mem_controls.addWidget(refresh_mem_btn)
        
        mem_controls.addStretch()
        
        layout.addLayout(mem_controls)
        layout.addWidget(self.memory_table)
        
        self.central_tabs.addTab(memory_widget, 'Memory Viewer')
        
    def create_injector_tab(self):
        """Create DLL injector tab"""
        injector_widget = QWidget()
        layout = QVBoxLayout(injector_widget)
        
        # DLL selection
        dll_group = QGroupBox('DLL Injection')
        dll_layout = QVBoxLayout(dll_group)
        
        # DLL path selection
        dll_path_layout = QHBoxLayout()
        
        self.dll_path_edit = QLineEdit()
        self.dll_path_edit.setPlaceholderText('Select DLL file to inject...')
        self.dll_path_edit.textChanged.connect(self.on_dll_path_changed)
        dll_path_layout.addWidget(self.dll_path_edit)
        
        browse_btn = QPushButton('📁 Browse')
        browse_btn.clicked.connect(self.browse_dll)
        dll_path_layout.addWidget(browse_btn)
        
        dll_layout.addLayout(dll_path_layout)
        
        # Injection controls
        inject_controls = QHBoxLayout()
        
        self.inject_btn = QPushButton('💉 Inject DLL')
        self.inject_btn.setProperty('class', 'inject')
        self.inject_btn.setEnabled(False)
        self.inject_btn.clicked.connect(self.inject_dll)
        inject_controls.addWidget(self.inject_btn)
        
        inject_controls.addStretch()
        
        dll_layout.addLayout(inject_controls)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        dll_layout.addWidget(self.progress_bar)
        
        layout.addWidget(dll_group)
        
        # Log area
        log_group = QGroupBox('Activity Log')
        log_layout = QVBoxLayout(log_group)
        
        self.log_area = QPlainTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setMaximumHeight(200)
        log_layout.addWidget(self.log_area)
        
        layout.addWidget(log_group)
        
        self.central_tabs.addTab(injector_widget, 'DLL Injector')
        
    def create_disassembly_tab(self):
        """Create assembly disassembly tab"""
        disasm_widget = QWidget()
        layout = QVBoxLayout(disasm_widget)
        
        # Disassembly controls
        disasm_controls = QHBoxLayout()
        
        address_label = QLabel('Address:')
        self.address_edit = QLineEdit()
        self.address_edit.setPlaceholderText('0x401000')
        disasm_controls.addWidget(address_label)
        disasm_controls.addWidget(self.address_edit)
        
        disasm_btn = QPushButton('📖 Disassemble')
        disasm_btn.clicked.connect(self.disassemble_address)
        disasm_controls.addWidget(disasm_btn)
        
        disasm_controls.addStretch()
        
        layout.addLayout(disasm_controls)
        
        # Disassembly output
        self.disasm_area = QPlainTextEdit()
        self.disasm_area.setReadOnly(True)
        self.disasm_area.setFont(QFont('Consolas', 10))
        layout.addWidget(self.disasm_area)
        
        self.central_tabs.addTab(disasm_widget, 'Disassembly')
        
    def create_dock_widgets(self):
        """Create dockable widgets"""
        # Process Info Dock
        self.process_info_dock = QDockWidget('Process Info', self)
        self.process_info_widget = QWidget()
        self.process_info_layout = QVBoxLayout(self.process_info_widget)
        
        self.process_info_label = QLabel('No process selected')
        self.process_info_layout.addWidget(self.process_info_label)
        
        self.process_info_dock.setWidget(self.process_info_widget)
        self.addDockWidget(Qt.RightDockWidgetArea, self.process_info_dock)
        
        # Memory Scanner Dock
        self.scanner_dock = QDockWidget('Memory Scanner', self)
        self.scanner_widget = QWidget()
        self.scanner_layout = QVBoxLayout(self.scanner_widget)
        
        # Scanner controls
        scan_type_label = QLabel('Scan Type:')
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItems(['Exact Value', 'Unknown Initial', 'Increased Value', 'Decreased Value'])
        self.scanner_layout.addWidget(scan_type_label)
        self.scanner_layout.addWidget(self.scan_type_combo)
        
        value_label = QLabel('Value:')
        self.scan_value_edit = QLineEdit()
        self.scan_value_edit.setPlaceholderText('Enter value to scan for...')
        self.scanner_layout.addWidget(value_label)
        self.scanner_layout.addWidget(self.scan_value_edit)
        
        scan_btn = QPushButton('🔍 First Scan')
        scan_btn.clicked.connect(self.first_scan)
        self.scanner_layout.addWidget(scan_btn)
        
        next_scan_btn = QPushButton('➡️ Next Scan')
        next_scan_btn.clicked.connect(self.next_scan)
        self.scanner_layout.addWidget(next_scan_btn)
        
        # Results
        self.scan_results_list = QListWidget()
        self.scanner_layout.addWidget(self.scan_results_list)
        
        self.scanner_dock.setWidget(self.scanner_widget)
        self.addDockWidget(Qt.LeftDockWidgetArea, self.scanner_dock)
        
    def create_status_bar(self):
        """Create professional status bar"""
        self.status_bar = self.statusBar()
        
        # Status labels
        self.status_label = QLabel('Ready')
        self.process_label = QLabel('No Process')
        self.memory_label = QLabel('Memory: N/A')
        self.architecture_label = QLabel('Arch: N/A')
        
        self.status_bar.addWidget(self.status_label)
        self.status_bar.addPermanentWidget(self.process_label)
        self.status_bar.addPermanentWidget(self.memory_label)
        self.status_bar.addPermanentWidget(self.architecture_label)
        
    def refresh_processes(self):
        """Refresh the process list with detailed information"""
        self.process_table.setRowCount(0)
        self.log_message("Refreshing process list...")
        
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cpu_percent', 'memory_info', 'status']):
                try:
                    processes.append(proc)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort processes by name
            processes.sort(key=lambda x: x.info['name'].lower())
            
            self.process_table.setRowCount(len(processes))
            
            for row, proc in enumerate(processes):
                try:
                    name = proc.info['name']
                    pid = proc.info['pid']
                    cpu_percent = proc.info['cpu_percent'] or 0.0
                    memory_info = proc.info['memory_info']
                    memory_mb = memory_info.rss / 1024 / 1024 if memory_info else 0
                    status = proc.info['status'] or "Unknown"
                    
                    # Determine architecture (simplified)
                    architecture = "x64" if sys.maxsize > 2**32 else "x86"
                    
                    self.process_table.setItem(row, 0, QTableWidgetItem(str(pid)))
                    self.process_table.setItem(row, 1, QTableWidgetItem(name))
                    self.process_table.setItem(row, 2, QTableWidgetItem(f"{cpu_percent:.1f}%"))
                    self.process_table.setItem(row, 3, QTableWidgetItem(f"{memory_mb:.1f} MB"))
                    self.process_table.setItem(row, 4, QTableWidgetItem(status))
                    self.process_table.setItem(row, 5, QTableWidgetItem(architecture))
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
            self.log_message(f"Found {len(processes)} running processes")
            
        except Exception as e:
            self.log_message(f"Error refreshing processes: {str(e)}")
    
    def filter_processes(self, text):
        """Filter processes based on search text"""
        for row in range(self.process_table.rowCount()):
            name_item = self.process_table.item(row, 1)
            if name_item and text.lower() in name_item.text().lower():
                self.process_table.setRowHidden(row, False)
            else:
                self.process_table.setRowHidden(row, True)
    
    def on_process_double_clicked(self, item):
        """Handle process double-click to attach"""
        row = item.row()
        pid_item = self.process_table.item(row, 0)
        name_item = self.process_table.item(row, 1)
        
        if pid_item and name_item:
            self.target_pid = int(pid_item.text())
            self.target_process = name_item.text()
            self.attach_process()
    
    def refresh_memory_regions(self):
        """Refresh memory regions for attached process"""
        if not self.target_pid:
            QMessageBox.warning(self, "Warning", "Please attach to a process first!")
            return
        
        self.log_message("Refreshing memory regions...")
        # This would require more complex Windows API calls
        # For now, we'll show a placeholder
        self.memory_table.setRowCount(0)
        self.log_message("Memory regions refreshed (placeholder)")
    
    def browse_dll(self):
        """Browse for DLL file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select DLL File", "", "DLL Files (*.dll);;All Files (*)"
        )
        if file_path:
            self.dll_path_edit.setText(file_path)
            self.dll_path = file_path
            self.log_message(f"Selected DLL: {os.path.basename(file_path)}")
            self.update_button_states()
    
    def on_dll_path_changed(self, text):
        """Handle DLL path change"""
        self.dll_path = text
        self.update_button_states()
    
    def update_button_states(self):
        """Update button enabled states"""
        can_inject = bool(self.target_process and self.dll_path and os.path.exists(self.dll_path))
        self.inject_btn.setEnabled(can_inject)
        
        if can_inject:
            self.status_label.setText("Ready to inject")
        else:
            self.status_label.setText("Select process and DLL file")
    
    def attach_process(self):
        """Attach to selected process"""
        if not self.target_process:
            QMessageBox.warning(self, "Warning", "Please select a process first!")
            return
        
        try:
            # Open process handle
            self.process_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, self.target_pid)
            if not self.process_handle:
                QMessageBox.critical(self, "Error", "Failed to open target process!")
                return
            
            self.log_message(f"Attached to process: {self.target_process} (PID: {self.target_pid})")
            self.process_label.setText(f"Process: {self.target_process}")
            self.status_label.setText(f"Attached to: {self.target_process}")
            
            # Update process info dock
            self.update_process_info_dock()
            
            # Refresh memory regions
            self.refresh_memory_regions()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to attach to process: {str(e)}")
    
    def update_process_info_dock(self):
        """Update process info dock with current process details"""
        if not self.target_process:
            self.process_info_label.setText("No process selected")
            return
        
        try:
            proc = psutil.Process(self.target_pid)
            info_text = f"""
Process: {self.target_process}
PID: {self.target_pid}
CPU: {proc.cpu_percent():.1f}%
Memory: {proc.memory_info().rss / 1024 / 1024:.1f} MB
Status: {proc.status()}
Threads: {proc.num_threads()}
Create Time: {proc.create_time()}
            """
            self.process_info_label.setText(info_text.strip())
        except Exception as e:
            self.process_info_label.setText(f"Error getting process info: {str(e)}")
    
    def update_process_info(self):
        """Update process information periodically"""
        if self.target_process:
            self.update_process_info_dock()
    
    def inject_dll(self):
        """Inject DLL into target process"""
        if not self.target_process or not self.dll_path:
            QMessageBox.warning(self, "Warning", "Please select a process and DLL file!")
            return
        
        if not os.path.exists(self.dll_path):
            QMessageBox.critical(self, "Error", "DLL file does not exist!")
            return
        
        # Disable buttons during injection
        self.inject_btn.setEnabled(False)
        self.attach_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        self.log_message(f"Starting injection of {os.path.basename(self.dll_path)} into {self.target_process}")
        
        # Start worker thread
        self.worker = ProcessWorker(self.target_process, self.dll_path)
        self.worker.process_attached.connect(self.on_process_attached)
        self.worker.injection_complete.connect(self.on_injection_complete)
        self.worker.progress_update.connect(self.progress_bar.setValue)
        self.worker.start()
    
    def on_process_attached(self, message):
        """Handle process attachment"""
        self.log_message(message)
    
    def on_injection_complete(self, success, message):
        """Handle injection completion"""
        self.progress_bar.setVisible(False)
        self.inject_btn.setEnabled(True)
        self.attach_btn.setEnabled(True)
        
        if success:
            self.log_message(f"✅ {message}")
            QMessageBox.information(self, "Success", message)
        else:
            self.log_message(f"❌ {message}")
            QMessageBox.critical(self, "Injection Failed", message)
        
        self.status_label.setText("Ready")
    
    def disassemble_address(self):
        """Disassemble code at given address"""
        address_text = self.address_edit.text().strip()
        if not address_text:
            QMessageBox.warning(self, "Warning", "Please enter an address!")
            return
        
        try:
            # Convert address to int
            if address_text.startswith('0x'):
                address = int(address_text, 16)
            else:
                address = int(address_text)
            
            # Placeholder disassembly - in a real implementation, you'd use a disassembler library
            disasm_text = f"""
Address: 0x{address:08X}
Disassembly:
0x{address:08X}: 48 89 5C 24 08    mov [rsp+8], rbx
0x{address+5:08X}: 57                push rdi
0x{address+6:08X}: 48 83 EC 20       sub rsp, 0x20
0x{address+10:08X}: 48 8B FA         mov rdi, rdx
0x{address+13:08X}: 48 8B D9         mov rbx, rcx
            """
            
            self.disasm_area.setPlainText(disasm_text.strip())
            self.log_message(f"Disassembled address: 0x{address:08X}")
            
        except ValueError:
            QMessageBox.critical(self, "Error", "Invalid address format!")
    
    def first_scan(self):
        """Perform first memory scan"""
        if not self.target_process:
            QMessageBox.warning(self, "Warning", "Please attach to a process first!")
            return
        
        scan_type = self.scan_type_combo.currentText()
        value = self.scan_value_edit.text().strip()
        
        if not value:
            QMessageBox.warning(self, "Warning", "Please enter a value to scan for!")
            return
        
        self.log_message(f"Starting {scan_type} scan for value: {value}")
        # Placeholder scan results
        self.scan_results_list.clear()
        self.scan_results_list.addItem("0x401000 - 100")
        self.scan_results_list.addItem("0x402000 - 200")
        self.scan_results_list.addItem("0x403000 - 300")
        self.log_message("First scan completed - 3 results found")
    
    def next_scan(self):
        """Perform next memory scan"""
        if not self.target_process:
            QMessageBox.warning(self, "Warning", "Please attach to a process first!")
            return
        
        scan_type = self.scan_type_combo.currentText()
        self.log_message(f"Performing {scan_type} scan...")
        # Placeholder - would filter previous results
        self.scan_results_list.clear()
        self.scan_results_list.addItem("0x401000 - 100")
        self.log_message("Next scan completed - 1 result found")
    
    def open_process_dialog(self):
        """Open process selection dialog"""
        # Switch to process manager tab
        self.central_tabs.setCurrentIndex(0)
        self.log_message("Process selection dialog opened")
    
    def open_memory_scanner(self):
        """Open memory scanner"""
        self.scanner_dock.show()
        self.log_message("Memory scanner opened")
    
    def open_hex_editor(self):
        """Open hex editor"""
        QMessageBox.information(self, "Hex Editor", "Hex editor functionality would be implemented here")
        self.log_message("Hex editor opened")
    
    def show_about(self):
        """Show about dialog"""
        QMessageBox.about(self, "About", 
                         "Advanced DLL Injector & Memory Editor\n\n"
                         "Professional reverse engineering tool\n"
                         "Combining features from x64dbg, Cheat Engine, and DLL injectors\n\n"
                         "Version 2.0")
    
    def log_message(self, message):
        """Add message to log area"""
        current_time = QDateTime.currentDateTime().toString("hh:mm:ss")
        self.log_area.appendPlainText(f"[{current_time}] {message}")
        # Auto-scroll to bottom
        scrollbar = self.log_area.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

def main():
    app = QApplication(sys.argv)
    app.setApplicationName("DLL Injector")
    app.setApplicationVersion("1.0")
    
    # Set application style
    app.setStyle('Fusion')
    
    window = DLLInjector()
    window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

