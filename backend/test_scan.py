import asyncio
from sqlalchemy import select
from app.database.session import AsyncSessionLocal
from app.models.scan import Scan

async def run():
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(Scan).order_by(Scan.created_at.desc()).limit(1))
        s = res.scalar_one_or_none()
        if s:
            recon = s.summary_json.get('recon', {}) if s.summary_json else {}
            print('TLS:', recon.get('tls'))
            print('Technologies:', recon.get('technologies'))
            print('Scan Error:', s.error_message)
            print('Target ID:', s.target_id)
            print('Scan URL:', s.current_url)
            print('Scan Status:', s.status)
            print('Scan Created:', s.created_at)
        else:
            print("No scans")

asyncio.run(run())
