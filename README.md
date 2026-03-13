<p align="center">
      __________________
    .-'  \ _.-''-._ /  '-.
  .-/\   .'.      .'.   /\-.
 _'/  \.'   '.  .'   './  \'_
:======:======::======:======:  
 '. '.  \     ''     /  .' .'
   '. .  \   :  :   /  . .'
     '.'  \  '  '  /  '.'
       ':  \:    :/  :'
         '. \    / .'
           '.\  /.'    Safe Place For Your Information
             '\/'

</p>

A secure, REPL based password manager built in Rust with military-grade encryption.

## Features

- **AES-256-GCM encryption** for password storage
- **Argon2** key derivation for master key and action password
- **Password strength validation** using zxcvbn
- **Built-in password generator** (16-character alphanumeric)
- **Unix file permissions** (0600) for secure storage
- **External file support** for multiple vaults
- **Interactive REPL interface** with rustyline
- **hidden master-key input system** with rpassword

## Security

diamond uses industry-standard cryptography:

- **Encryption**: AES-256-GCM with random nonce per entry
- **Key Derivation**: Argon2 with random 16-byte salt
- **Memory Safety**: Zeroizing for sensitive data in memory
- **File Permissions**: Unix 0600 (owner read/write only)

All passwords are encrypted before storage. The master key never touches disk in plaintext.

## Installation

```bash
git clone https://github.com/mohammed-dev23/diamond.git
cd diamond
cargo run
```

The binary will be in `/diamond`.

## Usage

Launch the REPL:

```bash
./diamond or cargo run
```

### Commands

#### Add a password
```
add <username/email> <password> <id> <<Option: note> <<Option: external path>> 
```

Example:
```
add user@example.com MyP@ssw0rd github MyMasterKey123456
add user@example.com MyP@ssw0rd github MyMasterKey123456 <note>
add user@example.com MyP@ssw0rd github MyMasterKey123456 <note> <path>
add user@example.com MyP@ssw0rd github MyMasterKey123456 <> <path>
```

#### Get a password
```
get <id> <<Option: external path>>
```

Example:
```
get github <any.json>
```

#### List all entries
```
list <<Option: external path>>
```

Example:
```
list <any.json>
list
```

#### Search for an entry
```
search <id> <<<Option: external path>>> 
```

Example:
```
search instagram <any.json>
search instagram
```

#### Remove an entry
```
remove <id> <<<Option: external path>>>
```

Example:
```
remove instagram
remove instagram <any.json>
```

#### Generate a password
```
gp
```

#### Help
```
help -l                    # List all commands
help --<command>           # Detailed help for a command
```

#### Exit
```
exit
```

#### Clear terminal
```
clear
```

#### Export && Import
Export a vault:
```
export <the name of the export> <<<Option: external path>>>
```
Example:
```
export any.json
export <any.json> <idk.json>
```

Import a vault:
```
import <the name/path of the vault you want to import> <new name>
```

Example:
```
import <any.json> <new-any.json>
```

**Keep in mind** in order to import you'll need the **master-key** you used in export 

## Password Requirements

- **Master Key**: Minimum 16 characters, must pass strength validation
- **Master-Key Strength**: Strength validated against username/email context

Master-Key are rated as: Very Weak, Weak, Fair, Good, or Strong. diamond rejects Very Weak and Weak and Fair Master-key.

## File Storage

Default location: `~/diamond/`

- `gem.json` - Encrypted password database
- `gem.toml` - Config file

External vaults are stored at the specified path relative to `~`.

Each entry stores:
- `id`: id identifier
- `salt` : the salt used in encrypting
- `nonce`: the nonce used in encryptinh
- `note`: a note
- `date`: the date of creation
- `data`: Base64-encoded encrypted blob containing username/email/etc.. and password

## Building from Source

### Build

```bash
cargo build --release
```
## Security Considerations

⚠️ **Important**:

- Never share your master key
- The master key encrypts/decrypts your vault and every thing else
- Loss of master-key means permanent data loss
- Store vault backups securely

## Platform Support

- **Linux/Unix**: Full support with file permissions
- **macOS**: Full support with file permissions  
- **Windows**: Core functionality (no Unix permissions)

## Disclaimer

This software is provided as-is. Always maintain backups of your password vault. The authors are not responsible for data loss or security breaches.