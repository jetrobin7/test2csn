const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');  // To generate a secure reset token
const SuperAdmin = require('../models/SuperAdmin'); // Ensure this points to the correct model file

// Helper function to send password reset link
const sendResetLinkEmail = async (recipientEmail, resetToken) => {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });

    // Use a dynamic domain depending on the environment
    const domain = process.env.NODE_ENV === 'production' 
        ? 'https://yourdomain.com' // Replace with your production domain
        : 'http://localhost:3000'; // Use localhost for development

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: recipientEmail,
        subject: 'Password Reset Link',
        text: `You requested a password reset. Click the link below to reset your password: 
               \n\n${domain}/reset-password/${resetToken}`,  // Dynamic domain
    };

    try {
        await transporter.sendMail(mailOptions);
        return { success: true };
    } catch (error) {
        console.error('Error sending reset link email:', error.message);
        return { success: false, message: 'Failed to send reset link' };
    }
};

// Generate and send the password reset link
exports.sendResetCode = async (req, res) => {
    const { uname } = req.body; // Email is passed as uname in the form

    try {
        // Trim and sanitize the input email
        const email = uname.trim(); 

        console.log('Searching for email:', email); // Debugging log

        // Perform case-insensitive search for the email
        const admin = await SuperAdmin.findOne({ email: { $regex: new RegExp(`^${email}$`, 'i') } });

        if (!admin) {
            console.log('Admin not found for email:', email); // Debugging log
            return res.status(404).json({ message: 'Email not found!' });
        }

        // Generate a secure reset token (random string)
        const resetToken = crypto.randomBytes(20).toString('hex');

        // Set reset token and its expiration time (1 hour validity)
        admin.resetToken = resetToken;
        admin.resetTokenExpiresAt = new Date(Date.now() + 3600000); // 1 hour from now
        await admin.save();

        // Send the reset link with the token to the admin's email
        const emailResult = await sendResetLinkEmail(admin.email, resetToken);
        if (!emailResult.success) {
            return res.status(500).json({ message: emailResult.message || 'Failed to send reset link' });
        }

        return res.status(200).json({ message: 'Reset link sent successfully!' });
    } catch (error) {
        console.error('Error sending reset link:', error);
        res.status(500).json({ message: 'Error sending reset link!' });
    }
};

// Verify the reset token and allow password change
exports.verifyResetCode = async (req, res) => {
    const { resetToken } = req.params;  // Token from the URL
    const { newPassword, confirmPassword } = req.body;

    try {
        // Check if the reset token is valid
        const admin = await SuperAdmin.findOne({
            resetToken,
            resetTokenExpiresAt: { $gt: new Date() },
        });
        
        if (!admin) {
            console.log('Token is invalid or expired');
            return res.status(404).json({ message: 'Invalid or expired reset token!' });
        }

        // Ensure the new password and confirm password match
        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: 'Passwords do not match!' });
        }

        // Update the admin's password (hashed for security)
        admin.password = await bcrypt.hash(newPassword, 10); // Hashing the password
        admin.resetToken = undefined;  // Clear the reset token after use
        admin.resetTokenExpiresAt = undefined;  // Clear the expiration time
        await admin.save();

        res.status(200).json({ message: 'Password updated successfully!' });
    } catch (error) {
        console.error('Error verifying reset token:', error);
        res.status(500).json({ message: 'Internal Server Error' });
    }
};