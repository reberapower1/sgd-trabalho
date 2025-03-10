import pandas as pd 
import seaborn as sns 
import matplotlib.pyplot as plt

url = 'https://bit.ly/CDA_chile' 
df = pd.read_csv(url)

import pandas as pd
import matplotlib.pyplot as plt

# Contar votos por faixa etária
votos_populacao=df.groupby('population')['vote'].value_counts().unstack(fill_value=0)
votos_populacao.plot(kind='bar', stacked=True, xlabel="População", ylabel="Número de Votos", title="Distribuição de Votos por População")
plt.show()