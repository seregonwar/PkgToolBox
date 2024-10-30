# PKG Tool Box

[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/seregon)

## 🤝 Contributions Welcome!

**Contributions to the development are welcome!** If you have any ideas 💡 on how to improve the code, feel free to:

- ✉️ Message me privately on [X (Twitter)](https://twitter.com/SeregonWar)
- 🔧 Open a [Pull Request](https://github.com/)
- 🐛 Report an issue through [Issues](https://github.com/)

Currently, I am the only developer 👨‍💻 and handling all the work can be challenging. Any support is greatly appreciated! 🙌


## Description
PS4 PKG Tool is a tool for manipulating PS4 PKG files. It allows you to extract, inject, modify, and obtain information about PKG files.

## Contributions
- **[Sinajet](https://github.com/sinajet/)**: Creator of **[PS5-Game-Info](https://github.com/sinajet/PS5-Game-Info)**, used in the program to read `eboot.bin` packages from `.pkg` files and recognize whether they are fake or not.

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
- **Trophy Management**: Load, unpack, read, and manage trophy files.
- **Trophy Creator**: Create new trophy files for games, customizing icons, descriptions, and achievements based on specific game requirements or user preferences.
- **Wallpapers**: Explore, extract, and modify wallpapers included in the PKG, allowing for the customization of background images used in the system or game.
- **Passcode Bruteforce**: Perform brute force attacks on passcodes included in the PKG, enabling the recovery or access to protected files within the package.
- **Integration with OpenOrbis**: Utilize `orbis-pub-cmd.exe` for advanced PKG manipulation.

## Requirements
- Python 3.13+
- PyQt5
- pyinstaller (use only pyinstaller, tools like cx_freeze will compromise the proper functioning of the project)
- `orbis-pub-cmd.exe` (included in the OpenOrbis toolchain)

## Installation
1. Clone the repository:
    ```sh
    git clone https://github.com/seregonwar/PS4-PKG-Tool-Box.git
    cd PkgToolBox
    ```

2. Install the dependencies:
    ```sh
    pip install -r requirements.txt
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

## Roadmap

### Completed
- **PKG File Navigation**
  - [x] Addition of an advanced directory file explorer to navigate internally within PKG files.
  - [x] Advanced reading of information.
  - [x] Improvement in the analysis of values in hex format.
  - [x] PS5 PKG file support.
  - [x] Full support for PS3 PKG files, retail and debug are supported.
- **Trophy Support**
  - [x] Full support for `.trp` trophy files (PS4).
  - [x] Full support for `.ucp` trophy files (PS5).
- **Stability**
  - [x] Increased program stability.
  - [x] Improved error handling.
- **General Improvements**
  - [x] Various improvements and bug fixes.
### In Progress / Planned
- **PKG Support**
  - [ ] Full support for PS5 PKG files.
  - [ ] Advanced PKG file splitting.
  - [ ] Fpkg updates.
  - [ ] Implementation of PKGToolBox directly on PS4 and PS5 systems.
- **DLC Injection**
  - [ ] Implementation of the inject section for loading DLC directly into PKG packages.
- **Multi-platform Compatibility**
  - [ ] Implementation of the project on other platforms (e.g., Linux, macOS, etc.).
- **File Decryption**
  - [ ] Decryption of `.ESFM` files.

## GUI

![image](https://github.com/user-attachments/assets/ba7a84cf-bb8e-41a9-b57c-0d74e0eee3ef)
![image](https://github.com/user-attachments/assets/599a354e-c276-4542-bb1a-f571945d6897)

