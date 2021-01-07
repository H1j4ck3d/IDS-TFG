import json
import datetime
from kafka import KafkaConsumer

# Este codigo se ha utilizado para comprobar el funcionamiento del plugin apache-metron-bro-kafka

#Iniciamos un consumidor Kafka
consumer = KafkaConsumer('Zeek_IDS', bootstrap_servers=['localhost:9092'], value_deserializer=lambda x: json.loads(x.decode('utf-8')))

#Imprimimos por consola los mensajes
for message in consumer:
    now = datetime.datetime.now()
    print(message.value)
    message_json = {"version": 1, "time": now, "type": "IDS", "event": 'Data', "data": message.value}
    print(message_json)