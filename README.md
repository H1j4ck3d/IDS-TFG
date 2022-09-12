Final project - IDS using Machine Learning


Download the UNSW-NB15 dataset

Execute "dataset_balancing.py"

Build the ML model by executing either of the Machine Learning models: "RandomForestClassifier_extended.py" or "DecisionTreeClassifier_extended.py"


Installation instruction for the victim Ubuntu machine with Zeek:


1.	Install Ubuntu 18.04 LTS machine in Virtualbox
	- Uninstall Anaconda if necessary due to some interference with Zeek installation process

2.	Install Zeek following the manual guide:
	>> sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev
	>> curl https://download.zeek.org/zeek-3.0.11.tar.gz -output zeek-3.0.11.tar.gz
	>> tar -xzf zeek-3.0.11.tar.gz
	>> ./configure -- prefix=/home/<user>/Zeek
	>> make && make install

3.	Install Zeek-Kafka plugin:
	- See Github https://github.com/SeisoLLC/zeek-kafka

	a.Install librdkafka-1.4.4
	b.Install zeek-kafka plugin using zig
	c.Test the installation using 
		>> zeek -N Seiso::Kafka

4.	Install Kafka (Java 8+ necessary)
    	>> curl https://downloads.apache.org/kafka/2.6.0/kafka_2.13-2.6.0.tgz | tar xvz

5.	Install Anaconda again



Instructions to install Vagrant machine used as IDS:

1.	Follow “Agile Data Science 2.0” instructions to download and setup the Vagrant machine

2.	Modify “Vagrantfile” to create an internal network within Virtualbox with other virtual machines
	>> config.vm.network “private network” , ip:”<IP address to use>”, virtualbox__intnet:”<internal network name>”




Intructions to setup the ports and linking the VMs:
1.	Using Virtualbox, add internal network to the Ubuntu machine

2.	Midify “Vagrantfile” añadiendo:
	>> config.vm.network “private network” , ip:”<IP address to use>”, virtualbox__intnet:”<internal network name>”

3.	In the Ubuntu machine, modify the file etc/netplan/*.yaml
	>> enp0s8 \n dhcp4: false \n dhcp6: false \n addresses:[<IP address>]
	>> sudo netplan apply

4.	Now the two machines are connected in the internal network 



Setup instructions to send the data from Zeek to the model using Kafka and Spark:

1.	Connect to the Ubuntu machine using
	>>ssh <username>@127.0.0.1 -p <port to connect to vm>

2.	Initiate Zookeeper y Kafka servers in the Ubuntu machine:
	>> kafka/bin/zookeeper-server-start.sh kafka/config/zookeeper.properties
	>> kafka/bin/kafka-server-start.sh kafka/config/server.properties

3.	Start Zeek in the Ubuntu machine:
	>> PATH=/home/<username>/zeek/bin:$PATH
	>> zeekctl deploy

4.	In the Vagrant machine, execute zeek_streaming.py
	>> spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.11:2.4.4 zeek_streaming.py