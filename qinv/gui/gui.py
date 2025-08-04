import sys
from PySide6.QtWidgets import QApplication, QLabel, QWidget, QVBoxLayout

def main():
    app = QApplication(sys.argv)

    # Create a window
    window = QWidget()
    window.setWindowTitle("Hello from PySide6")

    # Add a layout and label
    layout = QVBoxLayout()
    label = QLabel("Hello, world!")
    layout.addWidget(label)

    window.setLayout(layout)
    window.resize(300, 100)
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()
