import datetime
import pandas as pd
from pandas import read_csv
from pyspark import SparkConf
from pyspark.context import SparkContext
from pyspark.sql.session import SparkSession
from pyspark.sql.types import *
from pyspark.ml.feature import StringIndexer
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
from collections import Counter

# Este codigo se utiliza para obtener un dataset balanceado a partir del dataset UNSW-NB15 utilizando SMOTE

# Iniciamos una sesion de Spark
conf= SparkConf().setAll([('spark.executor.memory', '8g'),('spark.driver.memory','8g')])
sc = SparkContext(conf=conf)

spark = SparkSession(sc)

print("Viewing the beggining of the dataset...")

# Se define el esquema que va a tener la tabla
schema = StructType([
    StructField('srcip', StringType(), True),
    StructField('sport', IntegerType(), True),
    StructField('dstip', StringType(), True),
    StructField('dsport',IntegerType(), True),
    StructField('proto',StringType() , True),
    StructField('state', StringType(), True),
    StructField('dur', DoubleType(), True),
    StructField('sbytes', IntegerType(), True),
    StructField('dbytes', IntegerType(), True),
    StructField('sttl', IntegerType(), True),
    StructField('dttl', IntegerType(), True),
    StructField('sloss', IntegerType(), True),
    StructField('dloss', IntegerType(), True),
    StructField('service', StringType(), True),
    StructField('Sload', DoubleType(), True),
    StructField('Dload', DoubleType(), True),
    StructField('Spkts',IntegerType(), True),
    StructField('Dpkts',IntegerType(), True),
    StructField('swin', IntegerType(), True),
    StructField('dwin', IntegerType(), True),
    StructField('stcpb', DoubleType(), True),
    StructField('dtcpb', DoubleType(), True),
    StructField('smeansz', IntegerType(), True),
    StructField('dmeansz', IntegerType(), True),
    StructField('trans_depth',IntegerType(), True),
    StructField('res_bdy_len',IntegerType(), True),
    StructField('Sjit',DoubleType(), True),
    StructField('Djit',DoubleType(), True),
    StructField('Stime',IntegerType(), True),
    StructField('Ltime', IntegerType(), True),
    StructField('Sintpkt',DoubleType(), True),
    StructField('Dintpkt',DoubleType(), True),
    StructField('tcprtt',DoubleType(), True),
    StructField('synack',DoubleType(), True),
    StructField('ackdat',DoubleType(), True),
    StructField('is_sm_ips_ports',IntegerType(), True),
    StructField('ct_state_ttl',IntegerType(), True),
    StructField('ct_flw_http_mthd',IntegerType(), True),
    StructField('is_ftp_login',IntegerType(), True),
    StructField('ct_ftp_cm',IntegerType(), True),
    StructField('ct_srv_src',IntegerType(), True),
    StructField('ct_srv_dst',IntegerType(), True),
    StructField('ct_dst_ltm',IntegerType(), True),
    StructField('ct_src_ltm',IntegerType(), True),
    StructField('ct_src_dport_ltm',IntegerType(), True),
    StructField('ct_dst_sport_ltm',IntegerType(), True),
    StructField('ct_dst_src_ltm',IntegerType(), True),
    StructField('attack_cat',StringType(), True),
    StructField('label',IntegerType(), True)])


# Cargamos la tabla y elegimos un sample (a elegir)
dataset = spark.read.csv("Dataset/dataset.csv", mode='DROPMALFORMED', schema=schema, header='false')
dataset.show(25)

# Solucionamos errores en la tabla
dataset = dataset.na.replace([" Fuzzers "," Shellcode ","Backdoor"," Reconnaissance "],[" Fuzzers","Shellcode","Backdoors","Reconnaissance"],"attack_cat")
dataset.select("attack_cat").distinct().show()

# Eliminamos las caracteristicas que no son basicas
features_to_drop_zeek = ['srcip','dstip','state','sttl','dttl','sloss','dloss','Sload','Dload','swin','dwin','stcpb','dtcpb','smeansz','dmeansz','trans_depth',
                   'res_bdy_len','Sjit','Djit','Stime','Ltime','Sintpkt','Dintpkt','tcprtt','synack','ackdat','is_sm_ips_ports',
                    'ct_state_ttl','ct_flw_http_mthd','is_ftp_login','ct_ftp_cm','ct_srv_src','ct_srv_dst','ct_dst_ltm',
                    'ct_src_ltm','ct_src_dport_ltm','ct_dst_sport_ltm','ct_dst_src_ltm']

dataset = dataset.drop(*features_to_drop_zeek)
dataset.show(25)

# Preprocesamiento de caracteristicas
string_features_zeek = ['proto','service','attack_cat']

# Indexacion de caracteristicas tipo string
for feature in string_features_zeek:
    str_indexer = StringIndexer(inputCol=feature, outputCol=feature+'_index', handleInvalid='keep')
    dataset_model = str_indexer.fit(dataset)
    dataset = dataset_model.transform(dataset)
    base_path = "."
    str_indexer_model_path = "{}/data/str_indexer_extended/str_indexer_model_extended_{}.bin".format(base_path,feature)
    dataset_model.write().overwrite().save(str_indexer_model_path)

dataset.show(25)
dataset.select("attack_cat","attack_cat_index").distinct().show()


# Equilibrio de entradas basado en attack_cat (utilizado para comprobar los resultados)
#noAttack = dataset.filter("attack_cat_index = 9.0")
#attack = dataset.filter("attack_cat_index != 9.0")
#noAttack = noAttack.randomSplit([0.1, 0.9])
#fixed_dataset = noAttack[0]
#fixed_dataset = fixed_dataset.unionByName(attack)

#Aplicamos la tecnica de SMOTE
now = datetime.datetime.now()
print (now.year, now.month, now.day, now.hour, now.minute, now.second)

pdataset = dataset.toPandas()
pfeatures = pdataset[['sport','dsport','proto_index','dur','sbytes','dbytes','service_index','Spkts','Dpkts']]
plabels = pdataset["attack_cat_index"]

counter = Counter(plabels)
print(counter)

# Codigo de undersample (utilizado para comprobar los resultados)
#undersample = RandomUnderSampler({9.0: 221845})
#pfeatures, plabels = undersample.fit_resample(pfeatures,plabels)
#counter = Counter(plabels)
#print(counter)

oversample = SMOTE(sampling_strategy='not majority')
pfeatures, plabels = oversample.fit_resample(pfeatures, plabels)

counter = Counter(plabels)
print(counter)

now = datetime.datetime.now()
print (now.year, now.month, now.day, now.hour, now.minute, now.second)

pdataset = pd.concat([pfeatures,plabels], axis=1)
pdataset.to_csv(r'Dataset/extended_dataset.csv', header=True, index=False)
print("Dataset saved to disk")
