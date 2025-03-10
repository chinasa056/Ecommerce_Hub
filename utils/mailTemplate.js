const signUpTemplate = (verifyLink, firstName) => {
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cohort 5 Class </title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333333;
                background-color: #2c2c2c; /* Dark background */
                margin: 0;
                padding: 0;
            }
            .container {
                width: 80%;
                margin: 20px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                background-color: #f4f4f4; /* Light grey background */
            }
            .header {
                background: #570e0e;
                padding: 20px;
                text-align: center;
                border-bottom: 1px solid #ddd;
                color: #ffffff;
                border-radius: 10px 10px 0 0;
            }
            .content {
                padding: 20px;
                color: #333333;
            }
            .button-container {
                text-align: center;
                margin: 20px 0;
            }
            .button {
                display: inline-block;
                background-color:  #fc7e7e; /* Green background */
                color: #131111;
                padding: 15px 30px;
                font-size: 18px;
                text-decoration: none;
                border-radius: 5px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                transition: background-color 0.3s ease;
            }
            .button:hover {
                background-color: #218838;
            }
            .footer {
                background: #570e0e;
                padding: 10px;
                text-align: center;
                border-top: 1px solid #ddd;
                font-size: 0.9em;
                color: #cccccc;
                border-radius: 0 0 10px 10px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>BlogIT App!</h1>
            </div>
            <div class="content">
                <p>Hello ${firstName},</p>
                <p>Thank you for signing up on Blog_IT App. We are excited to have you on board.</p>
                <p>Please click the button below to verify your account:</p>
                <div class="button-container">
                    <a href="${verifyLink}" class="button">Verify My Account</a>
                </div>
                <p>If you did not sign up on our platform, kindly ignore this email.</p>
                <p>Best regards,<br>BlogIT Team</p>
            </div>
            <div class="footer">
                <p>&copy; ${new Date().getFullYear()} . All rights reserved.</p>
            </div>  
        </div>
    </body>
    </html>
    
  
    
    `
}

module.exports = { signUpTemplate }


exports.forgotPasswordTemplate = (verifyLink, firstName) => {
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cohort 5 Class </title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333333;
                background-color: #2c2c2c; /* Dark background */
                margin: 0;
                padding: 0;
            }
            .container {
                width: 80%;
                margin: 20px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                background-color: #f4f4f4; /* Light grey background */
            }
            .header {
                background: #333333;
                padding: 20px;
                text-align: center;
                border-bottom: 1px solid #ddd;
                color: #ffffff;
                border-radius: 10px 10px 0 0;
            }
            .content {
                padding: 20px;
                color: #333333;
            }
            .button-container {
                text-align: center;
                margin: 20px 0;
            }
            .button {
                display: inline-block;
                background-color: #28a745; /* Green background */
                color: #ffffff;
                padding: 15px 30px;
                font-size: 18px;
                text-decoration: none;
                border-radius: 5px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                transition: background-color 0.3s ease;
            }
            .button:hover {
                background-color: #218838;
            }
            .footer {
                background: #333333;
                padding: 10px;
                text-align: center;
                border-top: 1px solid #ddd;
                font-size: 0.9em;
                color: #cccccc;
                border-radius: 0 0 10px 10px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>email message!</h1>
            </div>
            <div class="content">
                <p>Hello ${firstName},</p>
                <p>A password reset has been initiated on your account.</p>
                <p>Please click the button below to reset your password:</p>
                <div class="button-container">
                    <a href="${verifyLink}" class="button">Verify My Account</a>
                </div>
                <p>If you did not initiate this reset, kindly ignore this email.</p>
                <p>Best regards,<br>Blog_IT Team</p>
            </div>
            <div class="footer">
                <p>&copy; ${new Date().getFullYear()} . All rights reserved.</p>
            </div>  
        </div>
    </body>
    </html>
    
  
    `
};

exports.changePasswordTemplate = (verifyLink, firstName) => {
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Cohort 5 Class </title>
        <style>
            body {
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333333;
                background-color: #2c2c2c; /* Dark background */
                margin: 0;
                padding: 0;
            }
            .container {
                width: 80%;
                margin: 20px auto;
                padding: 20px;
                border: 1px solid #ddd;
                border-radius: 10px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
                background-color: #f4f4f4; /* Light grey background */
            }
            .header {
                background: #333333;
                padding: 20px;
                text-align: center;
                border-bottom: 1px solid #ddd;
                color: #ffffff;
                border-radius: 10px 10px 0 0;
            }
            .content {
                padding: 20px;
                color: #333333;
            }
            .button-container {
                text-align: center;
                margin: 20px 0;
            }
            .button {
                display: inline-block;
                background-color: #28a745; /* Green background */
                color: #ffffff;
                padding: 15px 30px;
                font-size: 18px;
                text-decoration: none;
                border-radius: 5px;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                transition: background-color 0.3s ease;
            }
            .button:hover {
                background-color: #218838;
            }
            .footer {
                background: #333333;
                padding: 10px;
                text-align: center;
                border-top: 1px solid #ddd;
                font-size: 0.9em;
                color: #cccccc;
                border-radius: 0 0 10px 10px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>email message!</h1>
            </div>
            <div class="content">
                <p>Hello ${firstName},</p>
                <p>Hello, you initiated a password change request</p>
                <p>Please click the button below to change your password</p>
                <div class="button-container">
                    <a href="${verifyLink}" class="button">change my password</a>
                </div>
                <p>If you did not initiate this request, kindly ignore and reset your password, kindly ignore this email.</p>
                <p>Best regards,<br>Blog-IT Team</p>
            </div>
            <div class="footer">
                <p>&copy; ${new Date().getFullYear()} . All rights reserved.</p>
            </div>  
        </div>
    </body>
    </html>
    
    
    `
}

