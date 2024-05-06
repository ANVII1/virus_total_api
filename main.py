import requests as req
import dotenv as de
import os
import time as t

VIRUS_TOTAL_API_KEY = de.get_key(".env","VIRUS_TOTAL_API_KEY")

class VirusTotalAPI:
    MAIN_ADRESS = "https://www.virustotal.com/api/v3/"
    _header = {"x-apikey" : VIRUS_TOTAL_API_KEY }#, "accept": "application/json", "content-type": "multipart/form-data"}

    @classmethod
    def get_upload_url(self) -> str:
        """
        virus total has  to upload big files \n 
        files bigger than 32mb needed to be uploaded on special link \n
        this function return the that special url to upload big file \n
        link can be used only once \n
        max file size to upload on that link is 650mb \n
        """
        api_url = self.MAIN_ADRESS + "files/upload_url"
        response = req.get(api_url, headers=self._header)
        return response.json()["data"]
    
    @classmethod
    def get_votes_on_file(self, analysis_id : str) -> dict:
        """
        Эта хуйня возвращает 400 BadReqest хотя запрос составлен как в доках, короче я маму разрабов на баклажан насаживал
        """
        api_url = self.MAIN_ADRESS + f"files/{analysis_id}/votes"
        response = req.get(api_url, headers=self.  _header)
        return response.json()["data"]

    @classmethod
    def get_votes_on_url(self, analysis_id : str ) -> dict:
        """
        Эта хуйня возвращает 400 BadReqest хотя запрос составлен как в доках, короче я маму разрабов на баклажан насаживал
        """
        api_url = self.MAIN_ADRESS + f"files/{analysis_id}/votes"
        response = req.get(api_url, headers=self._header)
        return response.json()  

    @classmethod
    def get_analysis_id_of_url(self,url:str) -> str:
        """
        
        """
        api_url = self.MAIN_ADRESS + "urls"
        response = req.post(api_url, headers=self._header, data={"url":url} )
        return response.json()["data"]["id"]

    @classmethod
    def get_analysis_id_of_file(self,filePath,url:str) -> str:
        """
        
        """
        with open(filePath, "rb") as file:

            files = {"file": (filePath, file)}
            response = req.post(url, headers=self._header, files=files)
            
            return response.json()["data"]["id"]
                   
    @classmethod
    def get_analysis_result(self,analysis_ID:str) -> dict:
        """
        
        """
        url = self.MAIN_ADRESS + f"analyses/{analysis_ID}"
        response = req.get(url, headers=self._header)

        return response.json()["data"]

class Analysis_file:
    def __init__(self,file_path) -> None:
        
        self.is_done : bool = False
        self.file_path : str = file_path

        self._id = self._get_analysis_id()        
        #self._votes = VirusTotalAPI.get_votes_on_file(self._id)
        self._result = self._get_analysis_result_with_waiting_qeque()
         
        self.is_done = True
    
    def _get_analysis_result_with_waiting_qeque(self) -> dict:
        """
        wait of result, becouse request to analysis can be qeuqued
        """
        for i in range(10):
            analyses_result = VirusTotalAPI.get_analysis_result(self._id)
            if analyses_result["attributes"]["status"] == "completed":
                
                # check, if last analysis more than 1 week before than 
                # reanalysis
                
                return analyses_result
            
            t.sleep(30)
            
        raise TimeoutError("Что то не так, слишком долго анализируется файл")

    def _get_analysis_id(self):
        
        filesize = os.path.getsize(self.file_path)
       
        if filesize < 30000000: # 0-30 MB

            url = VirusTotalAPI.MAIN_ADRESS + "files"            
        elif filesize < 650000000: # 30-650 MB

            url = VirusTotalAPI.get_upload_url()
        else:
            raise ValueError("File Too Big")  
                
        return VirusTotalAPI.get_analysis_id_of_file(self.file_path,url)       

    def __repr__(self) -> str:
        """
        Принимает json ответ от analyze_file
        Вовзращвет строку c представлением
        """        
        if not self.is_done:
            return None

        attributes = self._result["attributes"]
        stats = attributes["stats"]
        reperesentation = "/////// Общее" + "\n"   
        reperesentation += "Malware: " + str(stats["malicious"]) + "\n"
        reperesentation += "Clean: " + str(stats["undetected"])

        if stats["malicious"] != 0:
            reperesentation += "\n\n" + "/////// Обнаружения" + "\n"
            results : dict = attributes["results"]

            for engine_name in results.keys():
                
                engine_scan = results[engine_name]
                if engine_scan["result"] is None:
                    continue

                reperesentation += engine_name + ": " + str(engine_scan["result"]) + "\n" 

            return reperesentation

    def get_result(self) -> str:
        return repr(self)

class Analysis_url:
    def __init__(self,url:str) -> None:
        self.is_done = False
        self._id = VirusTotalAPI.get_analysis_id_of_url(url)
        self._result = VirusTotalAPI.get_analysis_result(self._id)
        # self._votes = VirusTotalAPI.get_votes_on_url(self._id)        
        self.is_done = True

    def __repr__(self) -> str:
        if not self.is_done:
            return "Analysis is not done"
        
        attributes = self._result["attributes"]
        stats = attributes["stats"]

        representation = "/////// Общее" + "\n"

        representation += "Нашли угрозу: " + str(stats["malicious"]) + "\n"
        representation += "Подозрений: " + str(stats["suspicious"]) + "\n"
        representation += "Не проверили: " + str(stats["undetected"]) + "\n"
        representation += "Безвредный: " + str(stats["harmless"])

        if stats["malicious"] != 0 or stats["suspicious"] != 0:
            representation += "\n\n" + "/////// Обнаружений: " + "\n"
        
            for engine_scan_name in attributes["results"].keys():
                engine_scan = attributes["results"][engine_scan_name]

                if engine_scan["result"] == "unrated" or engine_scan["result"] == "clean":
                    continue   

                representation += engine_scan_name + ": " + str(engine_scan["category"]) + "/" + str(engine_scan["result"]) + "\n"
        
        return representation
        
    def get_result(self):
        return repr(self)        

def main():

    # file analysis
    analysis_file = Analysis_file("C:/Users/Anvie/repos/antivirus/MDRG.exe")
    print(analysis_file)

    # url analysis
    analysis_url = Analysis_url("https://vk.com/")    
    print(analysis_url)

if __name__ == "__main__":
    main()