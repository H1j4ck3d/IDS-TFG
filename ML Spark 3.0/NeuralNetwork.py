import datetime
from pyspark import SparkConf
from pyspark.sql.types import *
from pyspark.context import SparkContext
from pyspark.sql.session import SparkSession
from pyspark.ml.feature import StringIndexer
from pyspark.ml.feature import VectorAssembler
from pyspark.ml.classification import MultilayerPerceptronClassifier
from pyspark.ml.evaluation import MulticlassClassificationEvaluator

# Iniciamos una sesion de Spark
print("Viewing the beggining of the dataset...")

conf= SparkConf().setAll([('spark.executor.memory', '8g'),('spark.driver.memory','8g')])
sc = SparkContext(conf=conf)
spark = SparkSession(sc)

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
    StructField('ct_src_ ltm',IntegerType(), True),
    StructField('ct_src_dport_ltm',IntegerType(), True),
    StructField('ct_dst_sport_ltm',IntegerType(), True),
    StructField('ct_dst_src_ltm',IntegerType(), True),
    StructField('attack_cat',StringType(), True),
    StructField('label',IntegerType(), True)])

# Cargamos la tabla y elegimos un sample (a elegir)
dataset = spark.read.csv("../Dataset/dataset.csv", mode='DROPMALFORMED', schema=schema, header='false')
dataset.show(25)

# Solucionamos errores en la tabla
dataset = dataset.na.replace([" Fuzzers "," Shellcode ","Backdoor"," Reconnaissance "],[" Fuzzers","Shellcode","Backdoors","Reconnaissance"],"attack_cat")
dataset.select("attack_cat").distinct().show()

features_to_drop= ['srcip','dstip','state','sttl','dttl','sloss','dloss','Sload','Dload','swin','dwin','stcpb','dtcpb','smeansz','dmeansz','trans_depth',
                   'res_bdy_len','Sjit','Djit','Stime','Ltime','Sintpkt','Dintpkt','tcprtt','synack','ackdat','is_sm_ips_ports',
                    'ct_state_ttl','ct_flw_http_mthd','is_ftp_login','ct_ftp_cm','ct_srv_src','ct_srv_dst','ct_dst_ltm',
                    'ct_src_ ltm','ct_src_dport_ltm','ct_dst_sport_ltm','ct_dst_src_ltm']

dataset = dataset.drop(*features_to_drop)
dataset.show(25)


string_features = ['proto','service','attack_cat']

# Indexacion de caracteristicas tipo string
for feature in string_features:
    str_indexer = StringIndexer(inputCol=feature, outputCol=feature+'_index', handleInvalid='keep')
    dataset_model = str_indexer.fit(dataset)
    dataset = dataset_model.transform(dataset)


vector_features= ['sport','dsport','proto_index','dur','sbytes','dbytes','service_index','Spkts','Dpkts']

# Transformamos todas las caracteristicas en un vector, que se incorpora como nueva caracteristica
vector_assembler = VectorAssembler(inputCols= vector_features, outputCol="features")
dataset = vector_assembler.transform(dataset)
dataset.show(25)

# Dividimos el dataset en train y test
splits = dataset.randomSplit([0.7, 0.3], 1234)
train = splits[0]
test = splits[1]

# Especificamos las capas que tiene la red neuronal layers = [9, 9, 9, 10]
layers = [9, 9, 9, 10]

now = datetime.datetime.now()
print (now.year, now.month, now.day, now.hour, now.minute, now.second)

# Creamos el modelo de red neuronal, lo entrenamos y realizamos la prediccion
mpc = MultilayerPerceptronClassifier(layers=layers, labelCol='attack_cat_index', featuresCol='features', seed=1234,
                                     predictionCol='prediction')
mpc = mpc.fit(train)

now = datetime.datetime.now()
print (now.year, now.month, now.day, now.hour, now.minute, now.second)
result = mpc.transform(test)
dataset.show(25)
result.show(25)

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
print("Recall (TPR) = {}".format(weightedRecall))

evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="truePositiveRateByLabel", metricLabel=0)
TPR0 = evaluator.evaluate(result)
print("TPR of Generic = {}".format(TPR0))

evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="truePositiveRateByLabel", metricLabel=1)
TPR1 = evaluator.evaluate(result)
print("TPR of Exploits= {}".format(TPR1))

evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="truePositiveRateByLabel", metricLabel=2)
TPR2 = evaluator.evaluate(result)
print("TPR of Fuzzers = {}".format(TPR2))

evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="truePositiveRateByLabel", metricLabel=3)
TPR3 = evaluator.evaluate(result)
print("TPR of DoS = {}".format(TPR3))

evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="truePositiveRateByLabel", metricLabel=4)
TPR4 = evaluator.evaluate(result)
print("TPR of Reconnaissance = {}".format(TPR4))

evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="truePositiveRateByLabel", metricLabel=5)
TPR5 = evaluator.evaluate(result)
print("TPR of Analysis = {}".format(TPR5))

evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="truePositiveRateByLabel", metricLabel=6)
TPR6 = evaluator.evaluate(result)
print("TPR of Backdoors = {}".format(TPR6))

evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="truePositiveRateByLabel", metricLabel=7)
TPR7 = evaluator.evaluate(result)
print("TPR of Shellcode = {}".format(TPR7))

evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="truePositiveRateByLabel", metricLabel=8)
TPR8 = evaluator.evaluate(result)
print("TPR of Worms = {}".format(TPR8))

evaluator = MulticlassClassificationEvaluator(labelCol="attack_cat_index", metricName="truePositiveRateByLabel", metricLabel=9)
TPR9 = evaluator.evaluate(result)
print("TPR of no attack = {}".format(TPR9))
