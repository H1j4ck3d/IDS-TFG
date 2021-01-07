import datetime
from pyspark import SparkConf
from pyspark.context import SparkContext
from pyspark.sql.session import SparkSession
from pyspark.sql.types import *
from pyspark.ml.feature import StringIndexer
from pyspark.ml.feature import VectorAssembler
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.evaluation import MulticlassClassificationEvaluator


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
dataset = spark.read.csv("./Dataset/dataset.csv", mode='DROPMALFORMED', schema=schema, header='false')
dataset.show(25)

# Solucionamos errores en la tabla
dataset = dataset.na.replace([" Fuzzers "," Shellcode ","Backdoor"," Reconnaissance "],[" Fuzzers","Shellcode","Backdoors","Reconnaissance"],"attack_cat")
dataset.select("attack_cat").distinct().show()

# Eliminamos las caracteristicas que no son basicas
features_to_drop_argus = ['srcip','dstip','state','swin','dwin','stcpb','dtcpb','smeansz','dmeansz','trans_depth',
                   'res_bdy_len','Sjit','Djit','Stime','Ltime','Sintpkt','Dintpkt','tcprtt','synack','ackdat','is_sm_ips_ports',
                    'ct_state_ttl','ct_flw_http_mthd','is_ftp_login','ct_ftp_cm','ct_srv_src','ct_srv_dst','ct_dst_ltm',
                    'ct_src_ltm','ct_src_dport_ltm','ct_dst_sport_ltm','ct_dst_src_ltm']

features_to_drop_zeek = ['srcip','dstip','state','sttl','dttl','sloss','dloss','Sload','Dload','swin','dwin','stcpb','dtcpb','smeansz','dmeansz','trans_depth',
                   'res_bdy_len','Sjit','Djit','Stime','Ltime','Sintpkt','Dintpkt','tcprtt','synack','ackdat','is_sm_ips_ports',
                    'ct_state_ttl','ct_flw_http_mthd','is_ftp_login','ct_ftp_cm','ct_srv_src','ct_srv_dst','ct_dst_ltm',
                    'ct_src_ltm','ct_src_dport_ltm','ct_dst_sport_ltm','ct_dst_src_ltm']

dataset = dataset.drop(*features_to_drop_zeek)
dataset.show(25)

# Preprocesamiento de caracteristicas
features = ['srcip','sport','dstip','dsport','proto','state','dur','sbytes','dbytes','sttl','dttl','sloss','dloss',
                    'service','Sload','Dload','Spkts','Dpkts','swin','dwin','stcpb','dtcpb','smeansz','dmeansz','trans_depth',
                   'res_bdy_len','Sjit','Djit','Stime','Ltime','Sintpkt','Dintpkt','tcprtt','synack','ackdat','is_sm_ips_ports',
                    'ct_state_ttl','ct_flw_http_mthd','is_ftp_login','ct_ftp_cm','ct_srv_src','ct_srv_dst','ct_dst_ltm',
                    'ct_src_ltm','ct_src_dport_ltm','ct_dst_sport_ltm','ct_dst_src_ltm','attack_cat','label']

string_features_argus = ['proto','state','service','attack_cat']
string_features_zeek = ['proto','service','attack_cat']

# Indexacion de caracteristicas tipo string
for feature in string_features_zeek:
    str_indexer = StringIndexer(inputCol=feature, outputCol=feature+'_index', handleInvalid='keep')
    dataset_model = str_indexer.fit(dataset)
    dataset = dataset_model.transform(dataset)
    base_path = "."
    str_indexer_model_path = "{}/data/str_indexer/str_indexer_model_RF_{}.bin".format(base_path, feature)
    dataset_model.write().overwrite().save(str_indexer_model_path)

dataset.show(25)

dataset.select("attack_cat","attack_cat_index").distinct().show()

vector_features_argus = ['sport','dsport','proto_index','state_index','dur','sbytes','dbytes','service_index','sttl',
                         'dttl','sloss','dloss','Sload','Dload','Spkts','Dpkts']

vector_features_zeek = ['sport','dsport','proto_index','dur','sbytes','dbytes','service_index','Spkts','Dpkts']

# Transformamos todas las caracteristicas en un vector, que se incorpora como nueva caracteristica
vector_assembler = VectorAssembler(inputCols= vector_features_zeek, outputCol="features")
dataset = vector_assembler.transform(dataset)
base_path = "."
vector_assembler_path = "{}/data/numeric_vector_assembler_RF.bin".format(base_path)
vector_assembler.write().overwrite().save(vector_assembler_path)
dataset.show(25)

# Dividimos el dataset en train y test
splits = dataset.randomSplit([0.7, 0.3], 1234)
train = splits[0]
test = splits[1]

# Creamos el modelo de Random Forest, lo entrenamos, lo guardamos y realizamos la prediccion
now = datetime.datetime.now()
print (now.year, now.month, now.day, now.hour, now.minute, now.second)

rf = RandomForestClassifier(labelCol='attack_cat_index', featuresCol='features', impurity='entropy', seed=1234,  maxBins=136, maxDepth=25,
                            featureSubsetStrategy='all', predictionCol='prediction')
rf = rf.fit(train)
model_output_path = "{}/data/RandomForest.bin".format( base_path)
rf.write().overwrite().save(model_output_path)
now = datetime.datetime.now()
print (now.year, now.month, now.day, now.hour, now.minute, now.second)

result = rf.transform(test)

#Creamos una funcion para el TPR
prediction_list = result.select("attack_cat_index", "prediction").toPandas()[["attack_cat_index","prediction"]].values.tolist()
def truePositiveRate(list, label):
    tot_count = 0
    true_count = 0
    for a in list:
        if a[0] == label:
            tot_count = tot_count + 1
            if a[1] == label:
                true_count = true_count + 1
    TPR = true_count/tot_count
    return TPR

# Evaluamos la prediccion
evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="accuracy")
accuracy = evaluator.evaluate(result)
print("Accuracy = {}".format(accuracy))

evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="weightedPrecision")
weightedPrecision = evaluator.evaluate(result)
print("weightedPrecision = {}".format(weightedPrecision))

evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="f1")
f1 = evaluator.evaluate(result)
print("f1 = {}".format(f1))

evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="weightedRecall")
weightedRecall = evaluator.evaluate(result)
print("Recall = {}".format(weightedRecall))

TPR0 = truePositiveRate(prediction_list, 0.0)
print("TPR of Generic = {}".format(TPR0))

TPR1 = truePositiveRate(prediction_list, 1.0)
print("TPR of Exploits= {}".format(TPR1))

TPR2 = truePositiveRate(prediction_list, 2.0)
print("TPR of Fuzzers = {}".format(TPR2))

TPR3 = truePositiveRate(prediction_list, 3.0)
print("TPR of DoS = {}".format(TPR3))

TPR4 = truePositiveRate(prediction_list, 4.0)
print("TPR of Reconnaissance = {}".format(TPR4))

TPR5 = truePositiveRate(prediction_list, 5.0)
print("TPR of Analysis = {}".format(TPR5))

TPR6 = truePositiveRate(prediction_list, 6.0)
print("TPR of Backdoors = {}".format(TPR6))

TPR7 = truePositiveRate(prediction_list, 7.0)
print("TPR of Shellcode = {}".format(TPR7))

TPR8 = truePositiveRate(prediction_list, 8.0)
print("TPR of Worms = {}".format(TPR8))

TPR9 = truePositiveRate(prediction_list, 9.0)
print("TPR of no attack = {}".format(TPR9))

