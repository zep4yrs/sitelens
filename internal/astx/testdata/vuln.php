<?php

function handler() {
    $id = $_GET['id'];
    $sql = "SELECT * FROM users WHERE id=" . $id;
    mysql_query($sql);
}

function safe_handler() {
    $name = $_GET['name'];
    echo htmlspecialchars($name);
}
