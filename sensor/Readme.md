## Sensor Design

`tcpdumpSensor` utilizes `tcpdump` executable to monitor data plane traffic for ICMP port unreachable messages. It parses `tcpdump` output and outputs lines 

    IP:port

to the FIFO. The FIFO name is configurable using the config file. 

`tcpdumpSensor` executes `tcpdumpCommand` expecting it in the same directory as `tcpdumpSensor` executable.
`tcpdumpCommand` contains `tcpdump` command with options.

## Configuration Details

`tcpdumpSensor` shares the same config file as `icmp_detector`.It reads the FIFO filename as `icmp_sensor_fifo` parameter in the "../common/config" config file. If `icmp_sensor_fifo` is not present in the config file, the FIFO name is set to "/tmp/icmpSensorFifo".

## Options

--pcapFile: if present playback from pcap file.
