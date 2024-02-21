<?php
// Database connection
$dbconn = pg_connect("host=localhost dbname=sports user=postgres password=Satya@123")
    or die('Could not connect: ' . pg_last_error());

// Get form data
$username = $_POST['username'];
$password = $_POST['password'];

// Insert data into database
$query = "INSERT INTO admin_credentials (username, password) VALUES ('$username', '$password')";
$result = pg_query($query);

if ($result) {
    // Redirect to success page or do something else
    header("Location: admin_login_success.html");
    exit();
} else {
    echo "Error: " . $query . "<br>" . pg_last_error($dbconn);
}

// Close connection
pg_close($dbconn);
?>
