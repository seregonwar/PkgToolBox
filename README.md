# PKG Tool Box

## Donation
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/seregon)

## 🤝 Contributions Welcome!

**Contributions to the development are welcome!** If you have any ideas 💡 on how to improve the code, feel free to:

- ✉️ Message me privately on [X (Twitter)](https://twitter.com/SeregonWar)
- 🔧 Open a [Pull Request](https://github.com/)
- 🐛 Report an issue through [Issues](https://github.com/)

Currently, I am the only developer 👨‍💻 and handling all the work can be challenging. Any support is greatly appreciated! 🙌

**P.S.** if you are able to use the OpenOrbis sdk you could be really useful. I would like to create a version of this application that can run directly on PlayStation so that I can manipulate pkg files directly from there! Contact me! ;)

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
- [x] Improvements and bug fixes.
- [x] PS5 pkg support
- [ ] Full support ps5 pkgs file
- [ ] Fpkg updates
- [ ] Advanced pkg file splitting.
- [ ] Implementation of the inject section for loading dlc directly into pkg packages.
- [x] Increased program stability and improved error handling.
- [ ] Implementation of the project on other platforms(e.g. linux, macos etc.).
- [ ] Implementation of PkgToolBox directly on ps4 and ps5 systems.

## GUI

![image](https://github.com/user-attachments/assets/a31614ec-631f-4284-bdcc-144be87fbebe)

