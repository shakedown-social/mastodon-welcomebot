import { Hono } from 'hono'
import { env } from 'hono/adapter'

async function verifyHMAC(key: string, body: string, receivedHmac: string): Promise<boolean> {
    const encoder = new TextEncoder();

    // Convert receivedHmac to ArrayBuffer
    const receivedHmacArray = new Uint8Array(receivedHmac.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));

    // Import the HMAC key
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        encoder.encode(key),
        {
            name: 'HMAC',
            hash: 'SHA-256'
        },
        false,
        ['verify']
    );

    // Verify the HMAC
    const isVerified = await crypto.subtle.verify(
        'HMAC',
        cryptoKey,
        receivedHmacArray.buffer,
        encoder.encode(body)
    );
    return isVerified;
}

async function createStatus(accessToken: string, username: string): Promise<void> {
    const url = 'https://shakedown.social/api/v1/statuses';
    var status = `Hey @${username} - welcome to Shakedown! Here are some tips:\n\n`;
    status += `- Use the local timeline to find initial people to follow. Once you are following 10+ people, use this tool to find more accounts you’ll enjoy https://followgraph.vercel.app/\n\n`;
    status += `- The official Mastodon phone apps aren't great - try Mammoth for iOS and Tusky for Android\n\n`;
    status += `- Following more people makes Mastodon more fun. It keeps your Home feed active. So follow away! You can always unfollow later.\n\n`;
    status += `If you have any questions, let me know!`;

    try {
        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
                'Idempotency-Key': username
            },
            body: JSON.stringify({
                status: status,
                visibility: 'direct'
            }),
        });

        if (!response.ok) {
            throw new Error(`Error while messaging ${username}! Http status: ${response.status}`);
        } else {
            console.log(`Successfully messaged ${username}`);
        }
    } catch (error) {
        console.error('Error:', error);
    }
}

type Bindings = {
  ACCESS_TOKEN: string,
  WEBHOOK_SECRET: string
}

const app = new Hono<{ Bindings: Bindings }>()

app.get('/', (c) => c.text('OK'))

app.post('/webhook', async (c) => {
    const fullSignature = c.req.header('X-Hub-Signature') || '';
    const signature = fullSignature.replace(/^sha256=/, '');
    const body = await c.req.text();
    console.log(body);

    if (await verifyHMAC(c.env.WEBHOOK_SECRET, body, signature)) {
        const message = 'Webhook signature is valid. Processing the request...'
        console.log(message);
        const username = JSON.parse(body)['object']['username'];
        await createStatus(c.env.ACCESS_TOKEN, username);
        return c.text(message);
    } else {
        const message = 'Webhook signature is not valid. Ignoring the request...'
        console.log(message);
        return c.text(message);
    }
})

export default app