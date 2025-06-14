<?php
$servername = "localhost";  // XAMPP default is "localhost"
$username = "root";         // Default username for XAMPP
$password = "";             // Default password is empty for XAMPP
$database = "mosrs";        // Your database name

// Create connection
$conn = new mysqli($servername, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}
?>
