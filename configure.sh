#!/bin/sh

echo "Host: "
read host
echo "Port: "
read port
echo "Username: "
read user
echo "Password: "
read -s pass
echo "From: "
read from
echo "To: "
read to
echo -e "\nAPI-Key: "
read key
echo "DL folder: "
read dl
echo "ST folder: "
read st


echo -e "$host\n$port\n$user\n$pass\n$from\n$to\n$key\n$dl\n$st" >> config
