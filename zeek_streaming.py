# Run with: spark-submit --packages org.apache.spark:spark-sql-kafka-0-10_2.11:2.4.4 zeek_streaming.py --args
from pyspark.sql.session import SparkSession
from pyspark.sql.types import *
import pyspark.sql.functions as F
from pyspark.ml.feature import StringIndexerModel
from pyspark.ml.feature import VectorAssembler
from pyspark.ml.classification import RandomForestClassificationModel

'''
import argparse
#Este apartado es opcional y se utiliza para introducir los datos del topic, IP addr y puerto manualmente

# Initiate parser
parser = argparse.ArgumentParser()

# Add short and long arguments
parser.add_argument('-a', '--address', help='IP address to read Kafka server')
parser.add_argument('-p', '--port', help='Port to read Kafka server')
parser.add_argument('-t', '--topic', help='Kafka topic name')

# Read arguments from command line
args = parser.parse_args()

# Checks
if args.address:
    ADDR = args.address
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

'''

DIR = "192.168.3.3:9092"
TOPIC = "Zeek_IDS"
base_path = "."

# Inicia un consumidor Kafka desde Spark
spark = SparkSession.builder.master('local').config('spark.jars.packages', 'org.apache.spark:spark-sql-kafka-0-10_2.11:2.4.4')\
        .config("spark.default.parallelism", 1).getOrCreate()

spark.conf.set("spark.sql.execution.arrow.enable", "true")

raw_data = spark.readStream.format("kafka").option("kafka.bootstrap.servers", DIR).option("subscribe", TOPIC)\
        .option('startingOffsets', 'latest').load()

schema = StructType([   
    StructField('conn', StructType([
        StructField('ts',StringType(), True),
        StructField('uid',StringType(), True),
        StructField('id.orig_h', StringType(), True),
        StructField('id.orig_p', IntegerType(), True),
        StructField('id.resp_h', StringType(), True),
        StructField('id.resp_p', IntegerType(), True),
        StructField('proto', StringType(), True),
        StructField('service', StringType(), True),
        StructField('duration', DoubleType(), True),
        StructField('orig_bytes', IntegerType(), True),
        StructField('resp_bytes', IntegerType(), True),
        StructField('conn_state', StringType(), True),
        StructField('local_orig',BooleanType(), True),
        StructField('local_resp', BooleanType(), True),
        StructField('missed_bytes', StringType(), True),
        StructField('history', StringType(), True),
        StructField('orig_pkts', IntegerType(), True),
        StructField('orig_ip_bytes', StringType(), True),
        StructField('resp_pkts', IntegerType(), True),
        StructField('resp_ip_bytes', StringType(), True),
        StructField('tunnel_parents', StringType(), True),
        ])),
    StructField('version', StringType(), True),
    StructField('type', StringType(), True),
    StructField('event', StringType(), True)
    ])

dataset = raw_data.select(F.from_json(F.col("value").cast("string"),schema).alias("dataset")).select("dataset.*")
dataset.printSchema()
print(type(dataset))


#Cambia el nombre de las columnas y extrae las caracteristicas a un Dataframe de Spark
schema_fixed = StructType([
        StructField('time',StringType(), True),
        StructField('uid',StringType(), True),
        StructField('srcip', StringType(), True),
        StructField('sport', IntegerType(), True),
        StructField('dstip', StringType(), True),
        StructField('dsport', IntegerType(), True),
        StructField('proto', StringType(), True),
        StructField('service', StringType(), True),
        StructField('dur', DoubleType(), True),
        StructField('sbytes', IntegerType(), True),
        StructField('dbytes', IntegerType(), True),
        StructField('state', StringType(), True),
        StructField('local_orig',BooleanType(), True),
        StructField('local_resp', BooleanType(), True),
        StructField('missed_bytes', StringType(), True),
        StructField('history', StringType(), True),
        StructField('Spkts', IntegerType(), True),
        StructField('orig_ip_bytes', StringType(), True),
        StructField('Dpkts', IntegerType(), True),
        StructField('resp_ip_bytes', StringType(), True),
        StructField('tunnel_parents', StringType(), True),
        ])

dataset2 = dataset.select(F.col("conn").cast(schema_fixed))
dataset3 = dataset2.select("conn.srcip", "conn.sport", "conn.dstip", "conn.dsport", "conn.proto", "conn.dur", "conn.sbytes",
                                "conn.dbytes", "conn.service","conn.Spkts", "conn.Dpkts")
dataset3.printSchema()
print(type(dataset3))

#Rellena los valores nulos con un 0 (prevencion de errores)
dataset3 = dataset3.fillna(0)

# Procesamiento de caracteristicas
string_indexer_models = {}
for column in ['proto','service','attack_cat']:
        string_indexer_model_path = "{}/data/str_indexer_extended/str_indexer_model_extended_{}.bin".format(base_path,column)
        string_indexer = StringIndexerModel.load(string_indexer_model_path)
        string_indexer_models[column] = string_indexer

for column in ['proto','service','attack_cat']:
    string_indexer_model = string_indexer_models[column]
    dataset3 = string_indexer_model.transform(dataset3)

vector_assembler_path = "{}/data/numeric_vector_assembler_RFE.bin".format(base_path)
vector_assembler = VectorAssembler.load(vector_assembler_path)
finalDataset = vector_assembler.transform(dataset3)

# Carga el modelo de Machine Learning y lo aplica a los datos recibidos
model_path = "{}/data/RandomForest_extended.bin".format(base_path)
model = RandomForestClassificationModel.load(model_path)
predictions = model.transform(finalDataset)

# Visualizacion de las predicciones en consola
predictions = predictions.withColumn("prediction", predictions.prediction.cast("string"))
predictions = predictions.na.replace(["0.0", "1.0", "2.0", "3.0", "4.0", "5.0", "6.0", "7.0", "8.0", "9.0"],["Generic", "Exploits","Fuzzers","DoS", "Reconnaisance","Analysis", "Backdoors","Shellcode","Worms","No ataque"],"prediction")
only_predictions = predictions.select("prediction","srcip","sport","dstip","dsport","proto",'proto_index','dur','sbytes','dbytes','service_index','Spkts','Dpkts')
only_predictions = only_predictions.na.fill("No ataque")
query = only_predictions.writeStream.outputMode("append").format("console").option("numRows",1000).option("truncate", False).start().awaitTermination()

