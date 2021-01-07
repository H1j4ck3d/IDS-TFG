import datetime
import pandas as pd
import seaborn as sn
import matplotlib.pyplot as plt
from pandas import read_csv
from pyspark import SparkConf
from pyspark.context import SparkContext
from pyspark.sql.session import SparkSession
from pyspark.sql.types import *
from pyspark.ml.feature import VectorAssembler
from pyspark.ml.classification import RandomForestClassifier
from pyspark.ml.evaluation import MulticlassClassificationEvaluator


# Iniciamos una sesion de Spark
#Esto se ha modificado puesto que daban problemas a la hora de utilizar todos los datos de Argus (No pasa con Zeek)

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
base_path = "."
vector_assembler_path = "{}/data/numeric_vector_assembler_RFE.bin".format(base_path)
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
                            featureSubsetStrategy= 'all', predictionCol='prediction')
rf = rf.fit(train)

now = datetime.datetime.now()
print (now.year, now.month, now.day, now.hour, now.minute, now.second)
model_output_path = "{}/data/RandomForest_extended.bin".format(base_path)
rf.write().overwrite().save(model_output_path)
result = rf.transform(test)

prediction_df = result.select("attack_cat_index", "prediction").toPandas()
prediction_list = prediction_df[["attack_cat_index","prediction"]].values.tolist()

#Creamos una funcion para el TPR
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

#Creamos una funcion para al FPR
def falsePositiveRate(list, label):
    tot_count = 0
    false_count = 0
    for a in list:
        if a[0] != label:
            tot_count = tot_count + 1
            if a[1] == label:
                false_count = false_count + 1
    FPR = false_count/tot_count
    return FPR


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
FPR0 = falsePositiveRate(prediction_list, 0.0)
print("TPR of Generic = {}, FPR of Generic = {}".format(TPR0, FPR0))

TPR1 = truePositiveRate(prediction_list, 1.0)
FPR1 = falsePositiveRate(prediction_list, 1.0)
print("TPR of Exploits= {}, FPR of Exploits = {}".format(TPR1, FPR1))

TPR2 = truePositiveRate(prediction_list, 2.0)
FPR2 = falsePositiveRate(prediction_list, 2.0)
print("TPR of Fuzzers = {}, FPR of Fuzzers = {}".format(TPR2, FPR2))

TPR3 = truePositiveRate(prediction_list, 3.0)
FPR3 = falsePositiveRate(prediction_list, 3.0)
print("TPR of DoS = {}, FPR of DoS = {}".format(TPR3, FPR3))

TPR4 = truePositiveRate(prediction_list, 4.0)
FPR4 = falsePositiveRate(prediction_list, 4.0)
print("TPR of Reconnaissance = {}, FPR of Reconnaissance = {}".format(TPR4, FPR4))

TPR5 = truePositiveRate(prediction_list, 5.0)
FPR5 = falsePositiveRate(prediction_list, 5.0)
print("TPR of Analysis = {}, FPR of Analysis = {}".format(TPR5, FPR5))

TPR6 = truePositiveRate(prediction_list, 6.0)
FPR6 = falsePositiveRate(prediction_list, 6.0)
print("TPR of Backdoors = {}, FPR of Backdoors = {}".format(TPR6, FPR6))

TPR7 = truePositiveRate(prediction_list, 7.0)
FPR7 = falsePositiveRate(prediction_list, 7.0)
print("TPR of Shellcode = {}, FPR of Shellcode = {}".format(TPR7, FPR7))

TPR8 = truePositiveRate(prediction_list, 8.0)
FPR8 = falsePositiveRate(prediction_list, 8.0)
print("TPR of Worms = {}, FPR of Worms = {}".format(TPR8, FPR8))

TPR9 = truePositiveRate(prediction_list, 9.0)
FPR9 = falsePositiveRate(prediction_list, 9.0)
print("TPR of no attack = {}, FPR of no attack = {}".format(TPR9, FPR9))

#Print a confusion matrix
prediction_df = prediction_df.replace([0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0],["Generic", "Exploits","Fuzzers","DoS", "Reconnaisance","Analysis", "Backdoors","Shellcode","Worms","Normal"])
confusion_matrix = pd.crosstab(prediction_df["attack_cat_index"], prediction_df["prediction"],
                               rownames=["Valor actual"], colnames=["Valor de la prediccion"])
fig = plt.figure(figsize=(20, 11))
sn.heatmap(confusion_matrix, annot=True, cmap="YlGnBu")
plt.show()
fig.savefig('confusion_matrix_rfe.png', dpi=fig.dpi)