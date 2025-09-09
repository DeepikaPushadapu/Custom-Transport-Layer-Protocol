
# IP addresses
src_ip="127.0.0.1"
dest_ip="127.0.0.1"

# Function to run the executables
run_executables() {
    for i in {1..5}; do
        # Calculate source and destination ports
        src_port=$((15000 + ($i - 1) * 2))
        dest_port=$((src_port + 1))

        # Run user1
        sleep 2
        ./user1 $src_ip $src_port $dest_ip $dest_port &

        # Run user2
        sleep 2
        ./user2 $dest_ip $dest_port $src_ip $src_port &

    done
}

# Call the function to run the executables
run_executables
