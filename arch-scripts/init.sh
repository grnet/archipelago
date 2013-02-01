#! /bin/bash

##########################
# Functions' definitions #
##########################

txtrst=$(tput sgr0)		# Reset text color
txtred=$(tput setaf 1)	# Make text red
txtgrn=$(tput setaf 2)	# Make text green

red_echo(){
	echo -e "${txtred}${1}${txtrst}"
}

grn_echo(){
	echo -e "${txtgrn}${1}${txtrst}"
}
