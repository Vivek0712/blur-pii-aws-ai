import os
import boto3
import matplotlib.pyplot as plt
import matplotlib.image as mpimg
import numpy as np
import io
from PIL import Image, ImageDraw, ImageFilter
import cv2
import math
import json




#### UTIL METHODS ####
def readImagefromS3(bucket, photo):
    s3 = boto3.resource('s3', region_name='us-east-1')
    bucket = s3.Bucket(bucket)
    object = bucket.Object(photo)
    response = object.get()
    file_stream = response['Body']
    image = Image.open(file_stream)
    return image

def readImagefromLocal(filepath):
    image = Image.open(filepath)
    return image

def PILimageToBytes(image,form="PNG"):
    img_byte_arr = io.BytesIO()
    image.save(img_byte_arr, format=form)
    img_byte_arr = img_byte_arr.getvalue()
    return img_byte_arr

def uploadtoS3(localSourcefile, bucket, obj):
    s3 = boto3.resource('s3')
    s3.Bucket(bucket).upload_file(localSourcefile, obj)
    
def getS3ObjectURL(bucket,key):
    s3 = boto3.client('s3')
    url = s3.generate_presigned_url('get_object', 
                                           Params = {'Bucket': bucket, 'Key': key},                                        ExpiresIn = 600)
    return url

def readTextfromS3(bucket,item):
    s3 = boto3.resource('s3')
    bucket = s3.Bucket(bucket)
    obj = bucket.Object(item)
    body = obj.get()['Body'].read().decode("utf-8")
    return body

def readTextFromLocal(filepath):
    f = open(filepath, "r")
    body = f.read()
    return body

def saveTextToLocal(text,filepath):
    with open(filepath, 'w+') as f:
        f.write(text)
        
def saveImageToLocal(image,filepath):
    image.save(filepath)


#### HElPER METHODS #####

def redactPII_Text(entities, clean_text):
    for NER in reversed(entities):
            clean_text = clean_text[:NER['BeginOffset']] + "[" + NER['Type'] + "]" + clean_text[NER['EndOffset']:]
    return clean_text

def blurmask(image,box):
    imgWidth, imgHeight = image.size
    left = imgWidth * box['Left']
    top = imgHeight * box['Top']
    width = imgWidth * box['Width']
    height = imgHeight * box['Height']

    mask = Image.new('L', image.size, 0)
    draw = ImageDraw.Draw(mask)
    draw.rectangle([left,top, left + width, top + height], fill=255) 
    blurred = image.filter(ImageFilter.GaussianBlur(52))
    image.paste(blurred, mask=mask)
    return image
    

def blurPII_Image(image, entities, boundingbox,text):
    
    for NER in reversed(entities):
            targetText = text[NER['BeginOffset']:NER['EndOffset']]
            if targetText not in boundingbox.keys():
                brokenstring = targetText.split(" ")
            else:
                brokenstring = []
                brokenstring.append(targetText)
            for targetText in brokenstring:
                if targetText not in boundingbox.keys():
                    pass
                else:
                    box = boundingbox[targetText]
                    image = blurmask(image,box)
            
            
    return image

def detect_pii_from_text(text, language_code="en"):
        comp_detect = boto3.client('comprehend')
        entities =""
        try:
            response = comp_detect.detect_pii_entities(
                Text=text, LanguageCode=language_code)
            entities = response['Entities']
            
        finally:
            return entities

def detect_text_from_image(image):
    

    client=boto3.client('rekognition')
    
    response=client.detect_text(Image={
                        'Bytes': PILimageToBytes(image),
                    })
                        
    textDetections=response['TextDetections']

    text_corpus = []
    text_bounding_box = {}
    for text in textDetections:
            if text["Type"] == 'WORD':
              
                text_corpus.append(text['DetectedText'])
                
                text_bounding_box[text['DetectedText']] = text["Geometry"]["BoundingBox"]
    final_text_corpus = " ".join(text_corpus)
    return final_text_corpus,text_bounding_box

def detect_redact_pii_from_text(text):
    entities = detect_pii_from_text(text)
    clean_text = redactPII_Text(entities, text)
    return clean_text





def detect_blur_pii_from_image(image):
    text,text_bounding_box = detect_text_from_image(image)
    entities = detect_pii_from_text(text)
    blurredimage = blurPII_Image(image, entities, text_bounding_box,text)
    return blurredimage


def detect_blur_pii_from_video(sourceVideopath,destVideoPath):
    
    client=boto3.client('rekognition')
    cap = cv2.VideoCapture(sourceVideopath)
    frame_width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    frame_height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    fps = int(cap.get(cv2.CAP_PROP_FPS))
    frame_count = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    duration = frame_count/fps
    fourcc = cv2.VideoWriter_fourcc(*'XVID')
    out = cv2.VideoWriter(destVideoPath, fourcc, fps, (frame_width, frame_height))
    frameRate = fps
    while(cap.isOpened()):
        frameId = cap.get(1) #current frame number
        ret, frame = cap.read()
        if (ret != True):
            break
        if (frameId % math.floor(frameRate) == 0):
            hasFrame, imageBytes = cv2.imencode(".jpg", frame)
            if(hasFrame):
                image = Image.fromarray(np.uint8(frame)).convert('RGB')
                blurredimage = detect_blur_pii_from_image(image)
                open_cv_image = np.array(blurredimage)
                out.write(open_cv_image)
                           
    cap.release()
    out.release()
    
    


##### USAGE ######


"""
PII Content Format: Text
Source: Local File
"""
def redact_text_Local_File(sourceTextFilePath, DestTextFilePath):
    textContent = readTextFromLocal(sourceTextFilePath)
    PIIRedactText = detect_redact_pii_from_text(textContent)
    saveTextToLocal(PIIRedactText, DestTextFilePath)

"""
PII Content Format: Text
Source: S3 Bucket
"""
def redact_text_S3_bucket(sourceS3bucket, sourceS3Object,destS3bucket, destS3Object):
    textContent = readTextfromS3(sourceS3bucket,sourceS3Object)
    PIIRedactText = detect_redact_pii_from_text(textContent)
    saveTextToLocal(PIIRedactText, "sourceS3Object.txt")
    uploadtoS3("sourceS3Object.txt", destS3bucket, destS3Object)
    os.remove("sourceS3Object.txt")
    

"""
PII Content Format: Image
Source: Local File
"""

def blur_PII_image_Local_File(sourceImageFilePath, DestImageFilePath):
    Sourceimage = readImagefromLocal(sourceImageFilePath)
    blurredimage = detect_blur_pii_from_image(Sourceimage)
    saveImageToLocal(blurredimage,DestImageFilePath)
    
"""
PII Content Format: Image
Source: S3 Bucket
"""
    
def blur_PII_image_S3_bucket(sourceS3bucket, sourceS3Object,destS3bucket, destS3Object):
    Sourceimage = readImagefromS3(sourceS3bucket, sourceS3Object)
    blurredimage = detect_blur_pii_from_image(Sourceimage)
    tempimage = "temp"+ sourceS3Object.split("/")[-1]
    saveImageToLocal(blurredimage,tempimage)
    uploadtoS3(tempimage, destS3bucket, destS3Object)
    os.remove(tempimage)
    

"""
PII Content Format: Video
Source: Local File
"""

def blur_PII_video_Local_File(sourceVideoFilePath, DestVideoFilePath, ):
    detect_blur_pii_from_video(sourceVideoFilePath,DestVideoFilePath)
    
"""
PII Content Format: Video
Source: S3 Bucket
"""
    
def blur_PII_video_S3_bucket(sourceS3bucket, sourceS3Object,destS3bucket, destS3Object):
    sourceVideoFilePath = getS3ObjectURL(sourceS3bucket, sourceS3Object)
    tempvideo = "temp"+ sourceS3Object.split("/")[-1]
    detect_blur_pii_from_video(sourceVideoFilePath,tempvideo)
    uploadtoS3(tempvideo, destS3bucket, destS3Object)
    os.remove(tempvideo)

##### DEMO ######    
    
def PII_text_image_video_demo():
    
    s3Bucket = "rek-pii"

    ## TEXT ##
    sourceTextFilePath = "piitext.txt"
    DestTextFilePath = "piitextredact.txt"
    sourceS3Object = "media/text/source/piitext.txt"
    destS3Object = "media/text/output/piitexts3.txt"
    
    redact_text_Local_File(sourceTextFilePath, DestTextFilePath)
    redact_text_S3_bucket(s3Bucket, sourceS3Object,s3Bucket, destS3Object)
    
    
    ## IMAGE ##

    sourceImageFilePath = "rawimage.png"
    DestImageFilePath = "piiblurredimage.png"
    sourceS3Object = "media/image/source/rawimage.png"
    destS3Object = "media/image/output/piiblurredimage.png"
    
    blur_PII_image_Local_File(sourceImageFilePath, DestImageFilePath)
    blur_PII_image_S3_bucket(s3Bucket, sourceS3Object,s3Bucket, destS3Object)
    
    ## VIDEO ##

    sourceVideoFilePath = "rawvideo.mp4"
    DestVideoFilePath = "piiblurredvideo.mp4"
    sourceS3Object = "media/video/source/rawvideo.mp4"
    destS3Object = "media/video/output/piiblurredvideo.mp4"
    
    blur_PII_video_Local_File(sourceVideoFilePath, DestVideoFilePath)
    blur_PII_video_S3_bucket(s3Bucket, sourceS3Object,s3Bucket, destS3Object)
    
    
PII_text_image_video_demo()
