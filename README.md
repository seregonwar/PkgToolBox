# PS4 PKG Tool Box

## 🤝 Contributions Welcome!

**Contributions to the development are welcome!** If you have any ideas 💡 on how to improve the code, feel free to:

- ✉️ Message me privately on [X (Twitter)](https://twitter.com/SeregonWar)
- 🔧 Open a [Pull Request](https://github.com/)
- 🐛 Report an issue through [Issues](https://github.com/)

Currently, I am the only developer 👨‍💻 and handling all the work can be challenging. Any support is greatly appreciated! 🙌

## Description
PS4 PKG Tool is a tool for manipulating PS4 PKG files. It allows you to extract, inject, modify, and obtain information about PKG files.

## Features
- **Extraction**: Extract specific files from a PKG.
- **Injection**: Inject new data into an existing PKG file.
- **Modification**: Modify the header of a PKG file.
- **Dump**: Perform a complete dump of the contents of a PKG.
- **Information**: Obtain detailed information about a PKG file.
- **File Explorer**: Navigate and manage files within the PKG using an integrated file explorer.
- **Hex Reader**: View and edit files in hexadecimal format.
- **Text Reader**: View and edit text files.
- **Delete**: Delete files from the PKG.
- **Trophy Management**: Load, read, and manage trophy files.
- **Integration with OpenOrbis**: Utilize `orbis-pub-cmd.exe` for advanced PKG manipulation.

## Requirements
- Python 3.x
- PyQt5
- pyinstaller and cx_freeze (for creating the executable)
- `orbis-pub-cmd.exe` (included in the OpenOrbis toolchain)

## Installation
1. Clone the repository:
    ```sh
    git clone https://github.com/seregonwar/PS4-PKG-Tool-Box.git
    cd PS4-PKG-Tool-Box
    ```

2. Install the dependencies:
    ```sh
    pip install -r requirements.txt
    ```

3. Ensure `orbis-pub-cmd.exe` is located in the `OrbisLibrary` directory:
    ```sh
    PS4-PKG-Tool-Box/
    ├── OrbisLibrary/
    │   └── orbis-pub-cmd.exe
    └── ...
    ```

## Usage
1. Run the application:
    ```sh
    python main.py
    ```

2. Use the GUI to interact with PKG files:
    - **Browse**: Select a PKG file to work with.
    - **Extract**: Extract specific files from the PKG.
    - **Inject**: Inject new data into the PKG.
    - **Modify**: Modify the header of the PKG.
    - **Dump**: Perform a complete dump of the PKG contents.
    - **Info**: Obtain detailed information about the PKG.
    - **File Explorer**: Navigate and manage files within the PKG.
    - **Hex Reader**: View and edit files in hexadecimal format.
    - **Text Reader**: View and edit text files.
    - **Delete**: Delete files from the PKG.
    - **Trophy Management**: Load, read, and manage trophy files.

## Next Steps
- [x] Addition of an advanced directory file explorer to navigate internally to PKG files.
- [x] Advanced reading of information.
- [x] Improvement in the analysis of values in hex format.
- [ ] add tools related to IDA Pro.
- [ ] Improvements and bug fixes.


## GUI
![image](https://github.com/user-attachments/assets/8cae42c5-6d63-4556-8a88-3ae9cca14b93)

![image](https://github.com/user-attachments/assets/9d559248-95a5-4f32-a0fb-13605e7a7de6)

![image](https://github.com/user-attachments/assets/b020fe51-7d44-4ee4-a8a4-de3e0a73a948)
