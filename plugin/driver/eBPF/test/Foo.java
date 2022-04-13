import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.lang.Thread;

public class Foo {
    public static void main(String[] args) {
        for (int i = 0 ; i < 10; i++) {
            try {
                Thread.sleep(1000);
                Runtime.getRuntime().gc();
                System.out.println("Enforced GC!");
            } catch (Exception e) {

            }
        }
    }

    /**
     * Socket 客户端请求
     *
     * @param address ip地址
     * @param port 端口
     * @param requestMsg 请求内容
     */
    public static void send(String address,int port, String requestMsg) {

        try {
            //创建Socket对象
            Socket socket=new Socket(address,port);
            /**
             * 根据输入输出流和服务端连接
             * 1）获取一个输出流，向服务端发送信息
             * 2）将输出流包装成打印流
             * 3）关闭输出流
             */
            OutputStream outputStream=socket.getOutputStream();
            PrintWriter printWriter=new PrintWriter(outputStream);
            printWriter.print(requestMsg);
            printWriter.flush();
            socket.shutdownOutput();

            //获取一个输入流，接收服务端的信息
            InputStream inputStream=socket.getInputStream();
            //包装成字符流，提高效率
            InputStreamReader inputStreamReader=new InputStreamReader(inputStream);
            //缓冲区
            BufferedReader bufferedReader=new BufferedReader(inputStreamReader);
            StringBuffer sb = new StringBuffer();
            //临时变量
            String temp=null;
            while((temp=bufferedReader.readLine())!=null){
                sb.append(temp).append("\n");
            }
            System.out.println("客户端接收服务端发送信息："+sb.toString());

            //关闭相对应的资源
            bufferedReader.close();
            inputStream.close();
            printWriter.close();
            outputStream.close();
            socket.close();
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
