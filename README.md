# PKG Tool Box
[![Github All Releases](https://img.shields.io/github/downloads/seregonwar/PkgToolBox/total.svg)]()
--
## Description
PkgToolBox is a tool for manipulating PS4 PKG files. It allows you to extract, inject, modify, and obtain information about PKG files.

## ☕ Support PkgToolBox Development

PkgToolBox is actively developed and maintained over time.  
If you find this tool useful and want to support its continued development, you can buy me a coffee on Ko-fi.

[![Support me on Ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/seregon)


## 🤝 Contributions Welcome!

**Contributions to the development are welcome!** If you have any ideas 💡 on how to improve the code, feel free to:

- ✉️ Message me privately on [X (Twitter)](https://twitter.com/SeregonWar)
- 🔧 Open a [Pull Request](https://github.com/)
- 🐛 Report an issue through [Issues](https://github.com/)

Currently, I am the only developer 👨‍💻 and handling all the work can be challenging. Any support is greatly appreciated! 🙌



## Contributions
- **[Sinajet](https://github.com/sinajet/)**: Creator of **[PS5-Game-Info](https://github.com/sinajet/PS5-Game-Info)**, used in the program to read `eboot.bin` packages from `.pkg` files and recognize whether they are fpkg or not.
- **[HoppersPS4](https://github.com/HoppersPS4)**: Creator of c++ version [Waste_Ur_Time](https://github.com/HoppersPS4/Waste_Ur_Time) rewritten and implemented in PS4_Passcode_Bruteforcer.py module.

If I forgot to add anyone below, please let me know on [X](https://x.com/SeregonWar)!
## Features
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
    git clone https://github.com/seregonwar/PkgToolBox.git
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
<img width="1340" height="944" alt="Screenshot 2025-12-17 alle 13 44 38" src="https://github.com/user-attachments/assets/890e9463-7241-4ad2-a5e7-2c1b1cc5c9d9" />


