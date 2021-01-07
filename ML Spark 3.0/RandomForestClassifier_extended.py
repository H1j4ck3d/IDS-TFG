import datetime
from pyspark import SparkConf
from pyspark.context import SparkContext
from pyspark.sql.session import SparkSession
from pyspark.sql.types import *
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
    StructField('sport', IntegerType(), True),
    StructField('dsport',IntegerType(), True),
    StructField('proto_index',DoubleType(), True),
    StructField('dur', DoubleType(), True),
    StructField('sbytes', IntegerType(), True),
    StructField('dbytes', IntegerType(), True),
    StructField('service_index', DoubleType(), True),
    StructField('Spkts',IntegerType(), True),
    StructField('Dpkts',IntegerType(), True),
    StructField('attack_cat_index',DoubleType(), True)])


# Cargamos la tabla y elegimos un sample (a elegir)
dataset = spark.read.csv("./Dataset/extended_dataset.csv", mode='DROPMALFORMED', schema=schema, header='false')
dataset.show(25)
print(dataset.count())

# Transformamos todas las caracteristicas en un vector, que se incorpora como nueva caracteristica
vector_features_argus = ['sport','dsport','proto_index','state_index','dur','sbytes','dbytes','service_index','sttl',
                         'dttl','sloss','dloss','Sload','Dload','Spkts','Dpkts']

vector_features_zeek = ['sport','dsport','proto_index','dur','sbytes','dbytes','service_index','Spkts','Dpkts']

vector_assembler = VectorAssembler(inputCols= vector_features_zeek, outputCol="features")
dataset = vector_assembler.transform(dataset)
dataset.show(25)

# Dividimos el dataset en train y test
splits = dataset.randomSplit([0.7, 0.3], 1234)
train = splits[0]
test = splits[1]

# Creamos el modelo de Random Forest, lo entrenamos y realizamos la prediccion
now = datetime.datetime.now()
print (now.year, now.month, now.day, now.hour, now.minute, now.second)

rf = RandomForestClassifier(labelCol='attack_cat_index', featuresCol='features', seed=1234,  maxBins=136,
                            maxDepth=25, featureSubsetStrategy= 'all')
rf = rf.fit(train)

now = datetime.datetime.now()
print (now.year, now.month, now.day, now.hour, now.minute, now.second)

result = rf.transform(test)


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