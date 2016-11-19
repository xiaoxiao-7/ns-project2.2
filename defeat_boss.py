import time
import os
import random

# Use the current time as the seed
seed_time = random.seed()
# Generate the random number
random_number = random.randint(1,32767)

def boss_next_move():
	random_number = random.randint(1,32767)
	return ((int(random_number) & 3)+1)

def anti_boss(boss_move):
	if boss_move == 1:
		return 4
	elif boss_move ==2: 
		return 1
	elif boss_move ==3:
		return 2
	else: 
		return 3


student_ID = "0540015"
print(student_ID)

def defeat_boss():
	i=0
	while i <1000:
		boss_move = boss_next_move()
		print (anti_boss(boss_move))
		i = i+1

defeat_boss()
