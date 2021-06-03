#!/usr/bin/python
import re, os
import datetime
import sys
import optparse
import logging
import time

global logger;

class Lock_Analyzer:
    def __init__(self, logPath, threshold = 10, threadPos = 8, timeStampPos = 7):
        logger.info("Will analyze log file (" + logPath + ").");
        self.logPath = logPath;
        self.threshold = threshold;
        self.threadPos = threadPos;
        self.timeStampPos = timeStampPos;
        self.threadFilePosix = '_log.log';
        self.theadLockPosix = '_locks.log';
        self.threadFilePath = r'./ThreadFiles'
        self.lockerFilePath = r'./LockerFiles'
        self.lockPairsMap = {
            'lock_shared': 'unlock_shared',
            'lock_upgrade': 'unlock_upgrade',
            'unlock_upgrade_and_lock': 'unlock_and_lock_upgrade'
            };
        self.lockLogsMap = {
            'lock_shared': ['lock_shared(): Start lock_shared with addr', 'lock_shared(): lock_shared with addr'],
            'unlock_shared': ['unlock_shared(): Start unlock_shared with addr', 'unlock_shared(): unlock_shared with addr'],
            'lock_upgrade': ['lock_upgrade(): Start lock_upgrade with addr', 'lock_upgrade(): lock_upgrade with addr'],
            'unlock_upgrade': ['unlock_upgrade(): Start unlock_upgrade with addr', 'unlock_upgrade(): unlock_upgrade with'],
            'unlock_upgrade_and_lock': ['unlock_upgrade_and_lock(): Start unlock_upgrade_and_lock with addr', 'unlock_upgrade_and_lock(): unlock_upgrade_and_lock with addr'],
            'unlock_and_lock_upgrade': ['unlock_and_lock_upgrade(): Start unlock_and_lock_upgrade with addr', 'unlock_and_lock_upgrade(): unlock_and_lock_upgrade with addr']
            };
        self.analyzeSum = {};
    
    def closeThreadFiles(self, FilesMap):
        for key, value in FilesMap.items():
            if value is not None:
                value.close();

    def __del__(self):
        logger.info("will clean resources");
        logger.info("logs can be found from directory ./logs");

    def getThreadFile(self, FilesMap, key, posix):
        if not os.path.isdir(self.threadFilePath):
            os.mkdir(self.threadFilePath);
        if key not in FilesMap.keys():
            f = open(self.threadFilePath + r'/' + key + posix, 'w');
            FilesMap[key] = f;
        return FilesMap[key];

    def splitLogWithThreadId(self, threadFilesMap):
        log = open(self.logPath, 'r');
        for line in log.readlines():
            if line.find('SharedMutexImpl.h') == -1:
                continue;
            threadId = line.split(' ')[self.threadPos - 1];
            if threadId is None:
                continue;
            file = self.getThreadFile(threadFilesMap, threadId, self.threadFilePosix);
            file.write(line);
        self.closeThreadFiles(threadFilesMap);
        log.close();

    def getLockInfo(self, line):
        try:
            lockId = line.strip('\n').split(' ')[-1].split('0x')[1];
            if lockId is None:
                return None, None, None
            for key in self.lockLogsMap.keys():
                if line.find(self.lockLogsMap[key][1]) != -1:
                    timeStamp = self.getTimeStamp(line);
                    return lockId, key, timeStamp;
            return None, None, None;
        except Exception as ex:
            logger.warning(str(ex));
            logger.warning("error happened when handling: " + line.strip('\n'));
            return None, None, None


    def analyzeThreadFile(self, fileName, threadId):
        log = open(fileName, 'r');
        lockState = {};
        tmpLockResult = {};
        lockResult = {};
        for line in log.readlines():
            lockId, lockType, timeStamp = self.getLockInfo(line);
            if lockId is None:
                continue;
            if lockId not in lockState.keys():
                lockState[lockId] = {
                    'lock_shared': 0,
                    'lock_upgrade': 0,
                    'unlock_upgrade_and_lock': 0};

                tmpLockResult[lockId] = {
                    'lock_shared':[],
                    'lock_upgrade': [],
                    'unlock_upgrade_and_lock':[] };
                
                lockResult[lockId] = {
                    'lock_shared':[],
                    'lock_upgrade': [],
                    'unlock_upgrade_and_lock':[] };
            if lockType in lockState[lockId].keys():
                if lockState[lockId][lockType] != 0:
                    logger.warning("Detected recursive lock for thread: " + threadId + " with lock id: " + lockId + " with lock type: " + lockType + " at " + timeStamp)
                    self.addAnalyzeResult('Recursive Locker', [threadId, lockId, lockType, timeStamp]);
                lockState[lockId][lockType] += 1;
                record = [timeStamp, None, None];
                tmpLockResult[lockId][lockType].append(record);
            else:
                pairedLockType = None;
                for key, value in self.lockPairsMap.items():
                    if lockType == value:
                        pairedLockType = key;
                        break;
                if lockState[lockId][pairedLockType] == 0:
                    continue;
                lockState[lockId][pairedLockType] -= 1;
                tmpLockResult[lockId][pairedLockType][-1][1] = timeStamp;
                tmpLockResult[lockId][pairedLockType][-1][2] = (self.getTime(timeStamp) - self.getTime(tmpLockResult[lockId][pairedLockType][-1][0])).seconds;
                lockResult[lockId][pairedLockType].append(tmpLockResult[lockId][pairedLockType][-1]);
                tmpLockResult[lockId][pairedLockType].pop();
        
        for lockId in lockState.keys():
            for lockType in lockState[lockId].keys():
                if lockState[lockId][lockType] != 0:
                    lockResult[lockId][lockType] += tmpLockResult[lockId][lockType];
                    
        self.storeLockDetails(threadId, lockResult);
        log.close();

    def storeLockDetails(self, threadId, lockResult):
        if not os.path.isdir(self.lockerFilePath):
            os.mkdir(self.lockerFilePath);
        f = open(self.lockerFilePath + r'/' + threadId + self.theadLockPosix, 'w');
        for key in lockResult.keys():
            f.write("Lock Id: " + key + "\n");
            for lockType, records in lockResult[key].items():
                f.write("Lock Type: " + lockType + "\n");
                for record in records:
                    if record[1] is None: 
                        logger.error("there is possible deadlock for thread " + threadId + " with lock id " + key + " with type " + lockType + " at " + record[0]);
                        self.addAnalyzeResult('No released locker', [threadId, key, lockType, record[0]]);
                        f.write(record[0] + " " + " " + " " + " " + "\n");
                    else:
                        if int(record[2]) >= int(self.threshold):
                            self.addAnalyzeResult('long lock holder', [threadId, key, lockType, record[0], record[1], record[2]]);
                        f.write(record[0] + " " + str(record[1]) + " " + str(record[2]) + "\n");
        f.close();

    def addAnalyzeResult(self, record_name, record):
        if record_name not in self.analyzeSum.keys():
            self.analyzeSum[record_name] = [];
        self.analyzeSum[record_name].append(record);

    def calculateLockTime(self):
        threadFilesMap = {};
        self.splitLogWithThreadId(threadFilesMap);
        for threadId in threadFilesMap.keys():
            self.analyzeThreadFile(self.threadFilePath + r'/' + threadId+self.threadFilePosix, threadId);
        logger.info("--------------------Summary-----------------------")
        for type in self.analyzeSum.keys():
            logger.info(type + ":");
            for record in self.analyzeSum[type]:
                printInfo = "";
                for item in record:
                    printInfo += str(item) + " ";
                logger.info(printInfo);
            logger.info("=============================================");

    def getTime(self, timeStamp):
        return datetime.datetime.strptime(timeStamp.strip('Zz'), "%Y-%m-%dT%H:%M:%S.%f");

    def getTimeStamp(self, line):
        timeStamp = line.split(' ')[self.timeStampPos - 1];
        if timeStamp is None:
            return None;
        return timeStamp.strip('<>');

class ToolKit:  
    @staticmethod
    def getFileContent(fileName):
        if fileName is None:
            return None
        content = []
        f = open(fileName, 'r')
        print("The content within " + fileName + " is:")
        for line in f.readlines():
            print(line.strip("\n"))
            content.append(line.strip("\n"))
        f.close()
        return content

    @staticmethod
    def initParser():
        parser = optparse.OptionParser();
        parser.description = "This tool is used to detect:\n \
            1) possible deadlock\n \
            2) recursive lock\n \
            3) the hold time of lock\n \
            Usage:\n \
                Lock_Analyzer.py -f log_path";
        parser.add_option("-f", "--filePath", action = "store", dest = "logPath", help = "the path of log");
        parser.add_option("-t", "--threshold", action = "store", dest = "threshold", help = "highlight the lockers which are hold longer than the threshold");
        return parser;
    
    @staticmethod
    def checkOption(options):
        if options.logPath is None:
            raise Exception("please specify the path of log");

    @staticmethod
    def initLogger():
        LOG_FORMAT = '%(levelname)s - %(asctime)s - %(filename)s - %(lineno)d - %(message)s';
        time_line = time.strftime('%Y%m%d%H%M', time.localtime(time.time()))
        global logger;
        logger = logging.getLogger();
        logger.setLevel(logging.DEBUG);
        logPath = r'./logs';
        if not os.path.isdir(logPath):
            os.mkdir(logPath);
        logfile = logPath + r'/log_' + time_line + r'.txt';
        fileHandler = logging.FileHandler(logfile);
        fileHandler.setLevel(logging.DEBUG);
        fileHandler.setFormatter(logging.Formatter(LOG_FORMAT));
        logger.addHandler(fileHandler);
        streamHandler = logging.StreamHandler();
        streamHandler.setLevel(logging.DEBUG);
        streamHandler.setFormatter(logging.Formatter(LOG_FORMAT));
        logger.addHandler(streamHandler);
        return logger;

if __name__ == "__main__":
    parser = ToolKit.initParser();
    (options, args) = parser.parse_args();
    ToolKit.checkOption(options);
    ToolKit.initLogger();

    analyzer = Lock_Analyzer(options.logPath, options.threshold);
    analyzer.calculateLockTime();

     