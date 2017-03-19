"""Author : Kanimozhi Murugan"""
#Bin entropy calculation using statistical test suite based on Discrete fourier transform of the sequence. 
#The purpose is to detect the repetetive patterns that are near to each other in the sequence which would indicate
#a deviation from the assumption of randomness.
# Malware detection by entropy - ascii entropy and binary entropy
"""
Bin Entropy calculated based on 'Statistical Test Suite for Random and Pseudorandom Number Generators for Cryptographic Applications'
published by National Institute of Standards and Technology, U.S Department of Commerce
Source : http://csrc.nist.gov/groups/ST/toolkit/rng/documents/SP800-22rev1a.pdf
FFT - scipy.fftpack
pdfminer - PDF extraction tool
Malware detection by entropy based on 'Using Entropy analysis to find encrypted and packed malware'
published by IEEE Security and Privacy
ascii_entropy - entropy calculation on ascii contents of the file range(0 - 8)
"""

import sys, os, binascii              
import math, pdfminer
from scipy.fftpack import fft
from StringIO import StringIO
from pdfminer.pdfparser import PDFParser, PDFSyntaxError
from pdfminer.layout import LAParams
from pdfminer.converter import TextConverter
from pdfminer.pdfpage import PDFPage
from pdfminer.pdfinterp import PDFResourceManager, PDFPageInterpreter

d = os.listdir(".")
global l
byteArr = []
print "===================Detect encryption of files by Binary entropy====================="
print 
print 
print "Checking files within the path: ."
print

def pdf_r(fil):
    try:
        f = open(path+"/"+fil,"rb")
        mem = StringIO(f)
        parser = PDFParser(mem)#parser to the pdf
       # doc = PDFDocument(parser) 
        rsrcmgr = PDFResourceManager()
        retstr = StringIO()
        device = TextConverter(rsrcmgr, retstr,codec='utf-8', laparams=LAParams()) #PDF text
        #process_pdf(rsrcmgr, device, f) #extract the pdf content using pdfmanager
        inter = PDFPageInterpreter(rsrcmgr, device)
        caching = True
        pagenos = set()
        for page in PDFPage.get_pages(f, pagenos, maxpages=0, caching=caching, check_extractable=True):
            inter.process_page(page)
        f.close()  
        device.close()
        str = retstr.getvalue()
        retstr.close()
        #byteArr = map(ord, str) #map the extracted content to ASCII codes
        con = bin(int(binascii.hexlify(str),16))
        return bintropy(con)
    except PDFSyntaxError:    
        print "*****PDF Encrypted found in ",path+"\\"+fil+"*****"
        print
        l = l + 1

# calculate the ascii_frequency of each byte value in the file
# read the whole file into a byte array 'byteArr' 
def acsii_entropy(byteArr,fileSize):
    freqList = [0]*fileSize
    for b in range(256):
        ctr = 0.0
        for byte in byteArr:
            if byte == b:
                ctr += 1  
        freqList.append(float(ctr) / fileSize)
    # Shannon entropy
    ent = 0.0
    for freq in freqList:
        if freq > 0:
            ent = ent + (freq * math.log(freq, 2))
    ent = -ent
    print 'Shannon entropy (min bits per byte-character):',ent
   # print 'Min possible file size assuming max theoretical compression efficiency:'
   # print (ent * fileSize), 'in bits' 
   # print (ent * fileSize) / 8, 'in bytes'
   
########################## Bintropy ####################################################
def bintropy(con): #module for bintropy calculation
    s = 0.0
    slist = []
    dict = {'1':1,'0':-1} 
    for i in con[2:]:
        slist.append(dict[i]) # Convert 1 -> 1 and  0 -> -1 in the binary sequence "con"
        s = s + dict[i]
    dft = fft(slist)    #get the dft of the sequence
    ddft = dft[0:len(slist)/2] # get the substring of the dft with half the size
    modulus = [abs(i) for i in ddft] #modulus of the substring in the dft (abs value of the modulus)
    t = math.sqrt(math.log(1/0.05) * len(slist)) #95% threshold peak height (max peak height for any non-random sequence)  
    thoery_t = 0.95 * len(slist)/2 #expected theoretical number of peaks with heights > t
    peak = 0
    for m in modulus:
        if m < t:
            peak += 1  #actual observed number of peaks
    d = (peak - thoery_t)/math.sqrt(len(slist) * 0.95 * 0.05 /4)#normalized difference between the theoretical and observed freq of peaks
    ent = math.erfc(abs(d)/math.sqrt(2)) #complementary error function values to the normalized difference
    return ent
        #s_obs = abs(s)/math.sqrt(len(con[2:])) #test statistic of the binary content 
        #ent = math.erfc(s_obs/math.sqrt(2))
        # print path+"/"+fil,"Bin Entropy :",ent
        #if f.read(6) == "Salted":
        #   print "Salted"
        #byteArr = map(ord, f.read())
        #f.close()
        #fileSize = len(byteArr)
        #entropy(byteArr, fileSize)
l = 0        
for fname in d: #check each file in the directory "path"
    print "found ", fname
    if fname.lower().endswith('.pdf'): # .pdf file check
        ent = pdf_r(fname) #check if pdf content is extractable
        if ent is not None:
            print "File :\t",fname,"\t\tEntropy:",ent

    else: # if .txt or .doc file check
        f = open(fname)
        f.seek(88)
        con = bin(int(binascii.hexlify(f.read()),16)) #convert into binary sequence
        ent = bintropy(con) #calculate bin entropy of the file
        print "File :\t",fname,"\tEntropy :",ent
        if ent > 0.01: # detect if file is encrypted
            l += 1
            print "******Encrypted file found******", fname, "\n"
        else:
            print "file", fname, "does not appear to be encrypted"
            
print
print 
print "***********Found ",l,"Encrypted Files in the Path **************"

