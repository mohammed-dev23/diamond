# Diamond

A secure, REPL based password manager built in Rust with military-grade encryption.

## Features

- **AES-256-GCM encryption** for password storage
- **Argon2** key derivation for master key and action password
- **Password strength validation** using zxcvbn
- **Built-in password generator** (16-character alphanumeric)
- **Unix file permissions** (0600) for secure storage
- **External file support** for multiple vaults
- **Interactive REPL interface** with rustyline

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
add <username/email> <password> <id> <master-key> <<Option: note>> 
```

Example:
```
add user@example.com MyP@ssw0rd github MyMasterKey123456
add user@example.com MyP@ssw0rd github MyMasterKey123456 <note>
```

#### Get a password
```
get <id> <master-key> 
```

Example:
```
get github MyMasterKey123456
```

#### List all entries
```
list 
```

#### Search for an entry
```
search <id> 
```

#### Remove an entry
```
remove <id> <master-key>
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

### External Vaults

Use external files for separate password vaults:

```
external <path/file> <command> [arguments...]
```

Example:
```
external work.json add user@work.com P@ss123 slack MyKey123456
external work.json get slack MyKey123456 
external work.json list
```

## Password Requirements

- **Master Key**: Minimum 16 characters, must pass strength validation
- **Regular Passwords**: Strength validated against username/email context

Passwords are rated as: Very Weak, Weak, Fair, Good, or Strong. diamond rejects Very Weak and Weak and Fair passwords.

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

### Run tests

```bash
cargo test
```

## Security Considerations

⚠️ **Important**:

- Never share your master key
- The master key encrypts/decrypts your passwords
- Loss of master-key means permanent data loss
- Store vault backups securely

## Platform Support

- **Linux/Unix**: Full support with file permissions
- **macOS**: Full support with file permissions  
- **Windows**: Core functionality (no Unix permissions)

## Disclaimer

This software is provided as-is. Always maintain backups of your password vault. The authors are not responsible for data loss or security breaches.