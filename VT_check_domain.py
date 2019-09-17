"""
Raul Ramirez

Script para consultar dominios en VT.
Como ejecutarlo:
	- Introduce tu apiKey de VT
	- Introduce la ruta al fichero txt que contiene un listado de los dominios a consultar
"""


import requests

apikey = '<your_apiKey_here>'
file = '<path_to_the_file>'
VT_url_report = 'https://www.virustotal.com/vtapi/v2/url/report'

if __name__ == "__main__":

	f = open(file, 'r')
	num_dominios = len(f.readlines())
	f.close()

	with open(file, 'r') as file_to_read:
		# Variables para imprimir el porcentaje realizado
		count = 0
		# Lista para almacenar diccionarios de dominios flaggeados
		result_to_write = []

		# Leemos los dominios uno a uno
		for line in file_to_read:
			count += 1
			print("Procesando[{0}/{1}] ... {2:0.2f}%".format(count, num_dominios, float(count)*100/num_dominios))
			# Enviamos consulta
			params = {'apikey': apikey, 'resource': line}
			response = requests.get(VT_url_report, params)
			# Recibimos respuesta
			domain_result = response.json()
			# Comprobamos que el recurso exista en el dataset de VT
			if domain_result['response_code'] == 1:
				
				# Cogemos el diccionario de los motores de escaneo y sus resultados
				scans_results = domain_result['scans']
				# Cogemos solo los motores
				scans_engines = scans_results.keys()

				### Variables necesarias para buscar motores que hayan flaggeado el dominio
				flag_detected = False
				engines_flagged = []
				###
				# Para un dominio escogido, vemos si los motores de analisis lo flaggearon
				for engine in scans_engines:
					if scans_results[engine]['detected'] == True:
						flag_detected = True
						# engines_flagged sera una lista con los nombres de todos los motores que detectaron anomalo el dominio
						engines_flagged.append(str(engine))

				# Comprobamos si el flag esta activo para meter el dominio en una lista
				if flag_detected == True:
					# Resultados que nos interesan
					domain = domain_result['resource']
					positives_detections = str(domain_result['positives'])
					total_engines = str(domain_result['total'])
					# Metemos los campos en formato de diccionario para un mejor tratamiento futuro
					analysis_results = {'domain': domain, 'positives': positives_detections, 'total': total_engines, 'engines_flagged': engines_flagged}
					result_to_write.append(analysis_results)

		# Escribimos los dominios flaggeados a un fichero
		with open('output_domains.txt', 'w') as file_to_write:
			file_to_write.write("## Resultados del análisis ##\n")
			if len(result_to_write) > 0:
				for entry in result_to_write:
					file_to_write.write(str(entry)+"\n")
			else:
				file_to_write.write("Ningún dominio flaggeado!")

# End of Main()