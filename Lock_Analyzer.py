#!/usr/bin/python
import re, os
import datetime
import sys

class Lock_Analyzer:
    def __init__(self, logPath, threadPos = 8, timeStampPos = 7):
        print("Will analyze log file (" + logPath + ").");
        self.logPath = logPath;
        self.threadPos = threadPos;
        self.timeStampPos = timeStampPos;
        self.threadFilePosix = '_log.log';
        self.theadLockPosix = '_locks.log';
        
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
    
    def closeFiles(self, FilesMap):
        for key, value in FilesMap.items():
            if value is not None:
                value.close();

    def __del__(self):
        print("will clean resources");

    def getFile(self, FilesMap, key, posix):
        if key not in FilesMap.keys():
            f = open(key + posix, 'w');
            FilesMap[key] = f;
        return FilesMap[key];

    def splitLogWithThreadId(self, threadFilesMap):
        log = open(self.logPath, 'r');
        #threadFilesMap = {'empty': None};
        for line in log.readlines():
            if line.find('SharedMutexImpl.h') == -1:
                continue;
            threadId = line.split(' ')[self.threadPos - 1];
            if threadId is None:
                continue;
            file = self.getFile(threadFilesMap, threadId, self.threadFilePosix);
            file.write(line + "\n");
        self.closeFiles(threadFilesMap);
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

        f = open(threadId + self.theadLockPosix, 'w');
        for key in lockResult.keys():
            f.write("Lock Id: " + key + "\n");
            for lockType, records in lockResult[key].items():
                f.write("Lock Type: " + lockType + "\n");
                for record in records:
                    if record[1] is None: 
                        print("there is possible deadlock for thread " + threadId + " with lock id " + key + " with type " + lockType + " at " + record[0]);
                        f.write(record[0] + " " + " " + " " + " " + "\n");
                    else:
                        f.write(record[0] + " " + str(record[1]) + " " + str(record[2]) + "\n");

        f.close();
        log.close();

    def calculateLockTime(self):
        threadFilesMap = {};
        self.splitLogWithThreadId(threadFilesMap);
        for threadId in threadFilesMap.keys():
            self.analyzeThreadFile(threadId+self.threadFilePosix, threadId);

    def getTime(self, timeStamp):
        return datetime.datetime.strptime(timeStamp.strip('Zz'), "%Y-%m-%dT%H:%M:%S.%f");

    def getTimeStamp(self, line):
        timeStamp = line.split(' ')[self.timeStampPos - 1];
        if timeStamp is None:
            return None;
        return timeStamp.strip('<>');

if __name__ == "__main__":
    analyzer = Lock_Analyzer(sys.argv[1]);
    analyzer.calculateLockTime();

     