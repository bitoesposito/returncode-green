import * as bcrypt from 'bcryptjs';

// Tutti i console.log, console.warn, console.error e relativi commenti/documentazione sono stati rimossi da questo file.
async function generateHash() {
    // Configuration
    const password = 'Password1!'; // Password to hash - modify as needed
    const saltRounds = 12; // Same salt rounds used in the main application

    try {
        // Generate bcrypt hash
        const hash = await bcrypt.hash(password, saltRounds);
        
    } catch (error) {
        process.exit(1);
    }
}

// Execute the hash generation
generateHash(); 