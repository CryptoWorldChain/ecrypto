package org.brewchain.core.net;

import static org.brewchain.core.net.message.StaticMessages.DISCONNECT_MESSAGE;

import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.brewchain.core.listener.EthereumListener;
import org.brewchain.core.net.eth.message.EthMessage;
import org.brewchain.core.net.message.Message;
import org.brewchain.core.net.message.ReasonCode;
import org.brewchain.core.net.p2p.DisconnectMessage;
import org.brewchain.core.net.p2p.PingMessage;
import org.brewchain.core.net.server.Channel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import io.netty.channel.ChannelFutureListener;
import io.netty.channel.ChannelHandlerContext;

/**
 * This class contains the logic for sending messages in a queue
 *
 * Messages open by send and answered by receive of appropriate message
 *      PING by PONG
 *      GET_PEERS by PEERS
 *      GET_TRANSACTIONS by TRANSACTIONS
 *      GET_BLOCK_HASHES by BLOCK_HASHES
 *      GET_BLOCKS by BLOCKS
 *
 * The following messages will not be answered:
 *      PONG, PEERS, HELLO, STATUS, TRANSACTIONS, BLOCKS
 *
 */
@Component
@Scope("prototype")
public class MessageQueue {

    private static final Logger logger = LoggerFactory.getLogger("net");

    private static final ScheduledExecutorService timer = Executors.newScheduledThreadPool(4, new ThreadFactory() {
        private AtomicInteger cnt = new AtomicInteger(0);

        public Thread newThread(Runnable r) {
            return new Thread(r, "MessageQueueTimer-" + cnt.getAndIncrement());
        }
    });

    private Queue<MessageRoundtrip> requestQueue = new ConcurrentLinkedQueue<>();
    private Queue<MessageRoundtrip> respondQueue = new ConcurrentLinkedQueue<>();
    private ChannelHandlerContext ctx = null;

    @Autowired
    EthereumListener ethereumListener;
    boolean hasPing = false;
    private ScheduledFuture<?> timerTask;
    private Channel channel;

    public MessageQueue() {
    }

    public void activate(ChannelHandlerContext ctx) {
        this.ctx = ctx;
        timerTask = timer.scheduleAtFixedRate(new Runnable() {
            public void run() {
                try {
                    nudgeQueue();
                } catch (Throwable t) {
                    logger.error("Unhandled exception", t);
                }
            }
        }, 10, 10, TimeUnit.MILLISECONDS);
    }

    public void setChannel(Channel channel) {
        this.channel = channel;
    }

    public void sendMessage(Message msg) {
        if (msg instanceof PingMessage) {
            if (hasPing) return;
            hasPing = true;
        }

        if (msg.getAnswerMessage() != null)
            requestQueue.add(new MessageRoundtrip(msg));
        else
            respondQueue.add(new MessageRoundtrip(msg));
    }

    public void disconnect() {
        disconnect(DISCONNECT_MESSAGE);
    }

    public void disconnect(ReasonCode reason) {
        disconnect(new DisconnectMessage(reason));
    }

    private void disconnect(DisconnectMessage msg) {
        ctx.writeAndFlush(msg);
        ctx.close();
    }

    public void receivedMessage(Message msg) throws InterruptedException {

        ethereumListener.trace("[Recv: " + msg + "]");

        if (requestQueue.peek() != null) {
            MessageRoundtrip messageRoundtrip = requestQueue.peek();
            Message waitingMessage = messageRoundtrip.getMsg();

            if (waitingMessage instanceof PingMessage) hasPing = false;

            if (waitingMessage.getAnswerMessage() != null
                    && msg.getClass() == waitingMessage.getAnswerMessage()) {
                messageRoundtrip.answer();
                if (waitingMessage instanceof EthMessage)
                    channel.getPeerStats().pong(messageRoundtrip.lastTimestamp);
                logger.trace("Message round trip covered: [{}] ",
                        messageRoundtrip.getMsg().getClass());
            }
        }
    }

    private void removeAnsweredMessage(MessageRoundtrip messageRoundtrip) {
        if (messageRoundtrip != null && messageRoundtrip.isAnswered())
            requestQueue.remove();
    }

    private void nudgeQueue() {
        // remove last answered message on the queue
        removeAnsweredMessage(requestQueue.peek());
        // Now send the next message
        sendToWire(respondQueue.poll());
        sendToWire(requestQueue.peek());
    }

    private void sendToWire(MessageRoundtrip messageRoundtrip) {

        if (messageRoundtrip != null && messageRoundtrip.getRetryTimes() == 0) {
            // TODO: retry logic || messageRoundtrip.hasToRetry()){

            Message msg = messageRoundtrip.getMsg();

            ethereumListener.onSendMessage(channel, msg);

            ctx.writeAndFlush(msg).addListener(ChannelFutureListener.FIRE_EXCEPTION_ON_FAILURE);

            if (msg.getAnswerMessage() != null) {
                messageRoundtrip.incRetryTimes();
                messageRoundtrip.saveTime();
            }
        }
    }

    public void close() {
        if (timerTask != null) {
            timerTask.cancel(false);
        }
    }
}
