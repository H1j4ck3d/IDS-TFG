import argparse
import re

# Configurar el fichero local.zeek

# Inicia el parseador
parser = argparse.ArgumentParser()

# Añade los argumentos
parser.add_argument('-a', '--address', help='IP address to read Kafka server')
parser.add_argument('-p', '--port', help='Port to read Kafka server')
parser.add_argument('-t', '--topic', help='Kafka topic name')

# Lee los argumentos
args = parser.parse_args()

# Comprueba
if args.address:
    DIR = args.address
    print('Listening on IP address %s' % args.address)
else:
    print('ERROR: IP address not found')
    print('Exiting')
    exit()

if args.port:
    PORT = args.port
    print('Listening on port %s' % args.port)
else:
    print('ERROR: Port not found')
    print('Exiting')
    exit()

if args.topic:
    TOPIC = args.topic
    print('The Kafka topic is %s' % args.topic)
else:
    print('ERROR: Topic is missing')
    print('Exiting')
    exit()

path = '/home/vagrant/zeek/share/zeek/site/local.zeek'
file = open(path, 'r').readlines()
with open(path, 'w') as f:
    try:
        for line in file:
            if re.match('@load Apache/Kafka', line):
                print('Plugin already configured. Reconfiguring.')
                break
            else:
                f.write(line)
        plugin_lines = [
            '@load Apache/Kafka\n', 'redef Kafka::logs_to_send = set(Conn::LOG);\n', 'redef Kafka::topic_name = " % s";\n' % TOPIC,
            'redef Kafka::tag_json = T;\n', 'redef Kafka::kafka_conf = table(["metadata.broker.list"] = %s:%s);\n' % (DIR, PORT),
            'redef Kafka::additional_message_values = table(["version"] = "1", ["type"] = "IDS", ["event"] = "Data");\n']
        f.writelines(plugin_lines)
        print('Zeek has been successfully configured')

    except IOError:
        print('Error configuring Zeek')
