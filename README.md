# TFG
Trabajo de Fin de Grado - IDS utilizando Machine Learning

Instrucciones para la instalación de la maquina Ubuntu con Zeek:

1.	Preparación de la maquina Ubuntu utilizando Ubuntu 18.04 en VirtualBox
	-Desinstalar Anaconda si necesario

2.	Instalación de Zeek utilizando la guía de las dependencias requeridas:
	>> sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python-dev swig zlib1g-dev
	>> curl https://download.zeek.org/zeek-3.0.11.tar.gz -output zeek-3.0.11.tar.gz
	>> tar -xzf zeek-3.0.11.tar.gz
	>> ./configure -- prefix=/home/<user>/Zeek
	>> make && make install

3.	Instalación del plugin Zeek-Kafka:

	a.Primero, instalar librdkafka-1.4.2
	
		>> Ver https://github.com/apache/metron-bro-plugin-kafka
		
	b.Segundo, instalar el plugin (versión octubre 2020)
	
		>> git clone https://github.com/apache/metron-bro-plugin-kafka
		>> git reset <SHA1 versión octubre 2020>
		>> configure -- with-librdkafka=$librdkafka_root
		>> make
		>> sudo make install
		
	c.Comprobar si funciona usando: 
	
		>> zeek -N Apache::Kafka

4.	Instalación de Kafka: (necesario tener instalado Java 8+)
    	>> curl https://downloads.apache.org/kafka/2.6.0/kafka_2.13-2.6.0.tgz | tar xvz

5.	Instalar Anaconda de nuevo


Instrucciones para la instalación de la maquina Vagrant:

1.	Utilizando el libro “Agile Data Science 2.0” instalar la maquina Vagrant 

2.	Cambiar “Vagrantfile” para crear una red interna dentro de Virtualbox con las otras maquinas virtuales
	>> config.vm.network “private network” , ip:”<IP que queramos usar>”, virtualbox__intnet:”<nombre de la red interna>”


Instrucciones para la preparación de los puertos y la conexión de las VMs:
1.	Utilizando Virtualbox, añadir una red interna a la maquina Ubuntu 

2.	Para hacer lo mismo con la maquina Vagrant, modificar “Vagrantfile” añadiendo:
	>> config.vm.network “private_network”, ip:”<dirección IP>”, virtualbox__intnet:”<nombre de la red interna>”

3.	En la maquina Ubuntu, modificar fichero et/netplan/*.yaml
	>> enp0s8 \n dhcp4: false \n dhcp6: false \n addresses:[<dirección IP deseada>]
	>> sudo netplan apply

4.	Tras esto, las dos maquinas virtuales están conectadas usando la misma red interna y por lo tanto es posible utilizar las direcciones IP de las maquinas en dicha red interna para enviar los datos utilizando Kafka


Instrucciones para el envío de datos de Zeek a través de Kafka y Spark:

1.	Conectarse a la maquina Ubuntu usando:
	>>ssh <username>@127.0.0.1 -p <puerto a vm>

2.	Iniciar los servidores de Zookeeper y Kafka en la maquina Ubuntu:
	>> kafka/bin/zookeeper-server-start.sh kafka/config/zookeeper.properties
	>> kafka/bin/kafka-server-start.sh kafka/config/server.properties

3.	Iniciar Zeek en la maquina Ubuntu:
	>> PATH=/home/<username>/zeek/bin:$PATH
	>> zeekctl deploy

4.	En la maquina Vagrant, ejecutar el fichero de zeek_streaming.py
	>> spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.11:2.4.4 zeek_streaming.py
