import datetime
from pyspark import SparkConf
from pyspark.context import SparkContext
from pyspark.sql.session import SparkSession
from pyspark.sql.types import *
from pyspark.ml.feature import VectorAssembler
from pyspark.ml.classification import MultilayerPerceptronClassifier
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
dataset = spark.read.csv("/home/vagrant/TFG/Dataset/extended_dataset.csv", mode='DROPMALFORMED', schema=schema, header='true')
dataset.show(25)
print(dataset.count())

base_path = "/home/vagrant/TFG"

# Transformamos todas las caracteristicas en un vector, que se incorpora como nueva caracteristica
vector_features_argus = ['sport','dsport','proto_index','state_index','dur','sbytes','dbytes','service_index','sttl',
                         'dttl','sloss','dloss','Sload','Dload','Spkts','Dpkts']

vector_features_zeek = ['sport','dsport','proto_index','dur','sbytes','dbytes','service_index','Spkts','Dpkts']

vector_assembler = VectorAssembler(inputCols= vector_features_zeek, outputCol="features")
dataset = vector_assembler.transform(dataset)
vector_assembler_path = "{}/data/numeric_vector_assembler_RNE.bin".format(base_path)
vector_assembler.write().overwrite().save(vector_assembler_path)
dataset.show(25)

# Dividimos el dataset en train y test
splits = dataset.randomSplit([0.7, 0.3], 1234)
train = splits[0]
test = splits[1]

# Especificamos las capas que tiene la red neuronal
layers = [9, 9, 9, 10]

now = datetime.datetime.now()
print (now.year, now.month, now.day, now.hour, now.minute, now.second)

# Creamos el modelo de red neuronal, lo entrenamos, lo guardamos y realizamos la prediccion
mpc = MultilayerPerceptronClassifier(layers=layers, labelCol='attack_cat_index', featuresCol='features', seed=1234,
                                     predictionCol='prediction')
mpc = mpc.fit(train)

now = datetime.datetime.now()
print (now.year, now.month, now.day, now.hour, now.minute, now.second)

#model_output_path = "{}/data/RedNeuronal.bin".format( base_path)
#model.write().overwrite().save(model_output_path)
result = mpc.transform(test)


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



