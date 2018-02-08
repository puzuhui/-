package com.xiewei.modules.webservice.imp;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.net.ConnectException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.activiti.engine.repository.Model;
import org.dom4j.Document;
import org.dom4j.Element;
import org.dom4j.io.SAXReader;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.alipay.api.AlipayApiException;
import com.alipay.api.AlipayClient;
import com.alipay.api.DefaultAlipayClient;
import com.alipay.api.domain.AlipayTradeAppPayModel;
import com.alipay.api.internal.util.AlipaySignature;
import com.alipay.api.request.AlipayTradeAppPayRequest;
import com.alipay.api.response.AlipayTradeAppPayResponse;
import com.google.common.collect.Maps;
import com.xiewei.modules.sys.entity.User;
import com.xiewei.modules.sys.service.SystemService;
import com.xiewei.modules.webservice.UserService;
import com.xiewei.modules.webservice.dictionary.Status;
import com.xiewei.modules.weixin.utils.MyX509TrustManager;

@Controller
public class UserServiceImp implements UserService {

	@Autowired
	private SystemService service;

	/**
	 * 登录
	 */
	@Override
	public Map<String, Object> login(String userName, String pwd) {
		// TODO Auto-generated method stub
		Map<String, Object> maps = Maps.newHashMap();
		User user = service.findUser1(userName, pwd);
		if (user != null) {
			// String message = ErrorMessage.getMessage(Status.SUCCESS);
			List<User> list = new ArrayList<>();
			list.add(user);
			maps.put("status", Status.SUCCESS);
			maps.put("message", "登录成功");
			maps.put("result", list);
		} else {
			// String message = ErrorMessage.getMessage(Status.ERROR);
			maps.put("status", Status.ERROR);
			maps.put("message", "账号或密码不正确");
		}
		return maps;
	}

	/**
	 * 注册
	 */
	@Override
	public Map<String, Object> register(String loginname, String idcard,
			String name, String mobile, String password) {
		// TODO Auto-generated method stub
		Map<String, Object> maps = Maps.newHashMap();
		boolean r = service.register(loginname, idcard, name, mobile, password);
		if (r) {
			maps.put("status", Status.SUCCESS);
			maps.put("message", "注册成功");
		} else {
			maps.put("status", Status.ERROR);
			maps.put("message", "注册失败");
		}
		return maps;
	}

	/**
	 * 微信支付
	 */
	// 商户相关资料
	static String appid = "";
	static String partner = "";// 商户号
	static String partnerkey = "";//商户秘钥
	static String UNIFIED_ORDER_URL = "https://api.mch.weixin.qq.com/pay/unifiedorder";
	@Override
	public Map<String, Object> wechatpay(String body,String out_trade_no,int total_fee,String spbill_create_ip) {
		Map<String, Object> maps = new HashMap<String, Object>();
//		System.out.println("spbill_create_ip===" + spbill_create_ip);
		// 生产环境
		String notify_url = "http://192.168.188.122:8080/huaji/ws/user/goback";

		SortedMap<Object, Object> parameters = new TreeMap();
		parameters.put("appid", appid);
		parameters.put("mch_id", partner);
		parameters.put("nonce_str", createNoncestr());
		try {
			String wbody = new String(body.getBytes("ISO-8859-1"), "UTF-8");
			parameters.put("body", wbody);
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		parameters.put("out_trade_no", out_trade_no); // 订单id
		parameters.put("fee_type", "CNY");
		parameters.put("total_fee", String.valueOf(total_fee)); // 订单总金额，单位为分
		parameters.put("spbill_create_ip", spbill_create_ip);
		parameters.put("notify_url", notify_url);
		parameters.put("trade_type", "APP");
		// 设置签名
		String sign = createSign("UTF-8", parameters);
		parameters.put("sign", sign);
		// 封装请求参数结束
		String requestXML = getRequestXml(parameters);
		// 调用统一下单接口
		String result = httpsRequest(UNIFIED_ORDER_URL, "POST", requestXML);
		
		System.out.println("result===" + result);
		
		Map<String, String> parseXml = null;
		try {
			parseXml = parseXml(result);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		SortedMap<Object, Object> restultmap = new TreeMap<Object, Object>();   
		restultmap.put("appid", appid);
		restultmap.put("partnerid", partner);
		restultmap.put("prepayid", parseXml.get("prepay_id")); // 订单id
		restultmap.put("package", "Sign=WXPay");
		restultmap.put("noncestr", createNoncestr());
		restultmap.put("timestamp",Long.parseLong(String.valueOf(System.currentTimeMillis()).toString().substring(0, 10)));
		//二次签名
		String paySign = createSign("UTF-8", restultmap);
		restultmap.put("sign", paySign);
		// 封装请求参数结束
		String requestXML1 = getRequestXml(restultmap);
//		System.out.println("paySign===" + paySign);
//		System.out.println("requestXML1===" + requestXML1);
//		if (isTenpaySign("UTF-8", restultmap)) {
//			System.out.println("签名正确" +isTenpaySign("UTF-8", restultmap)) ;
//		}else{
//			System.out.println("签名错误" + isTenpaySign("UTF-8", restultmap));
//		}
		maps.put("status", "200");
		maps.put("result", restultmap);

		return maps;
	}
	
	
	//回调
	public void goback(Model model,HttpServletRequest request,HttpServletResponse response,
			HttpSession session) throws IOException{
		System.out.println("进入回调");
		   //读取参数  
        InputStream inputStream ;  
        StringBuffer sb = new StringBuffer();  
        inputStream = request.getInputStream();  
        String s ;  
        BufferedReader in = new BufferedReader(new InputStreamReader(inputStream, "UTF-8"));  
        while ((s = in.readLine()) != null){  
            sb.append(s);  
        }  
        in.close();  
        inputStream.close();  
  
        //解析xml成map  
        Map<String, String> m = new HashMap<String, String>();  
        try {
			m = parseXml(sb.toString());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}  
          
        //过滤空 设置 TreeMap  
        SortedMap<Object,Object> packageParams = new TreeMap<Object,Object>();        
        Iterator it = m.keySet().iterator();  
        while (it.hasNext()) {  
            String parameter = (String) it.next();  
            String parameterValue = m.get(parameter);  
              
            String v = "";  
            if(null != parameterValue) {  
                v = parameterValue.trim();  
            }  
            packageParams.put(parameter, v);  
        }  
  
        String resXml = ""; 
		// 判断签名是否正确
		if (isTenpaySign("UTF-8", packageParams)) {
				if ("SUCCESS".equals((String) packageParams.get("result_code"))) {
					// 这里是支付成功
					// ////////执行自己的业务逻辑////////////////
					String mch_id = (String) packageParams.get("mch_id"); // 商户号
					String openid = (String) packageParams.get("openid"); // 用户标识
					String out_trade_no = (String) packageParams.get("out_trade_no"); // 商户订单号
					String total_fee = (String) packageParams.get("total_fee");
					String transaction_id = (String) packageParams.get("transaction_id"); // 微信支付订单号
	
			} else {
				resXml = "<xml>" + "<return_code><![CDATA[FAIL]]></return_code>"
						+ "<return_msg><![CDATA[通知签名验证失败]]></return_msg>"
						+ "</xml> ";
				
			}
	
			// ------------------------------
			// 处理业务完毕
			// ------------------------------
			BufferedOutputStream out = new BufferedOutputStream(
					response.getOutputStream());
			out.write(resXml.getBytes());
			out.flush();
			out.close();
			
		}
	}
	

	/**
	 * 解析xml
	 * @param str
	 * @return
	 */
	static InputStream String2InputStream(String str) {
		ByteArrayInputStream stream = new ByteArrayInputStream(str.getBytes());
		return stream;
	}

	public static Map<String, String> parseXml(String str) throws Exception {
		// 将解析结果存储在HashMap中
		Map<String, String> map = new HashMap<String, String>();
		// 从request中取得输入流

		InputStream inputStream = String2InputStream(str);
		// 读取输入流
		SAXReader reader = new SAXReader();
		Document document = reader.read(inputStream);
		// 得到xml根元素
		Element root = document.getRootElement();
		// 得到根元素的所有子节点
		List<Element> elementList = root.elements();

		// 遍历所有子节点
		for (Element e : elementList) {
			//System.out.println(e.getName() + "|" + e.getText());
			map.put(e.getName(), e.getText());
		}

		// 释放资源
		inputStream.close();
		inputStream = null;
		return map;
	}

	/**
	 * 发送https请求
	 * 
	 * @param requestUrl
	 *            请求地址
	 * @param requestMethod
	 *            请求方式（GET、POST）
	 * @param outputStr
	 *            提交的数据
	 * @return 返回微信服务器响应的信息
	 */
	public static String httpsRequest(String requestUrl, String requestMethod,
			String outputStr) {
		try {
			// 创建SSLContext对象，并使用我们指定的信任管理器初始化
			TrustManager[] tm = { new MyX509TrustManager() };
			SSLContext sslContext = SSLContext.getInstance("SSL", "SunJSSE");
			sslContext.init(null, tm, new java.security.SecureRandom());
			// 从上述SSLContext对象中得到SSLSocketFactory对象
			SSLSocketFactory ssf = sslContext.getSocketFactory();
			URL url = new URL(requestUrl);
			HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
			// conn.setSSLSocketFactory(ssf);
			conn.setDoOutput(true);
			conn.setDoInput(true);
			conn.setUseCaches(false);
			// 设置请求方式（GET/POST）
			conn.setRequestMethod(requestMethod);
			conn.setRequestProperty("content-type",
					"application/x-www-form-urlencoded");
			// 当outputStr不为null时向输出流写数据
			if (null != outputStr) {
				OutputStream outputStream = conn.getOutputStream();
				// 注意编码格式
				outputStream.write(outputStr.getBytes("UTF-8"));
				outputStream.close();
			}
			// 从输入流读取返回内容
			InputStream inputStream = conn.getInputStream();
			InputStreamReader inputStreamReader = new InputStreamReader(
					inputStream, "UTF-8");
			BufferedReader bufferedReader = new BufferedReader(
					inputStreamReader);
			String str = null;
			StringBuffer buffer = new StringBuffer();
			while ((str = bufferedReader.readLine()) != null) {
				buffer.append(str);
			}
			// 释放资源
			bufferedReader.close();
			inputStreamReader.close();
			inputStream.close();
			inputStream = null;
			conn.disconnect();
			return buffer.toString();
		} catch (ConnectException ce) {
			// log.error("连接超时：{}", ce);
		} catch (Exception e) {
			// log.error("https请求异常：{}", e);
		}
		return null;
	}

	// 生成16位随机字符串
	public static String createNoncestr() {
		String chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
		String res = "";
		for (int i = 0; i < 16; i++) {
			Random rd = new Random();
			res += chars.charAt(rd.nextInt(chars.length() - 1));
		}
		return res;
	}

	/** 
     * 是否签名正确,规则是:按参数名称a-z排序,遇到空值的参数不参加签名。 
     * @return boolean 
     */  
    public static boolean isTenpaySign(String characterEncoding, SortedMap<Object, Object> packageParams) {  
        StringBuffer sb = new StringBuffer();  
        Set es = packageParams.entrySet();  
        Iterator it = es.iterator();  
        while(it.hasNext()) {  
            Map.Entry entry = (Map.Entry)it.next();  
            String k = (String)entry.getKey();  
            String v = (String)entry.getValue().toString();  
            if(!"sign".equals(k) && null != v && !"".equals(v)) {  
                sb.append(k + "=" + v + "&");  
            }  
        }  

        sb.append("key=" + partnerkey);  

        //算出摘要  
        String mysign = MD5Encode(sb.toString(), characterEncoding).toLowerCase();  
        String tenpaySign = ((String)packageParams.get("sign")).toLowerCase();  
  
        return tenpaySign.equals(mysign);  
    }  

    
	/**
	 * sign签名
	 * 
	 * @param characterEncoding
	 *            编码格式
	 * @param parameters
	 *            请求参数
	 * @return
	 */
	public static String createSign(String characterEncoding,
			SortedMap<Object, Object> parameters) {
		StringBuffer sb = new StringBuffer();
		Set es = parameters.entrySet();
		Iterator it = es.iterator();
		while (it.hasNext()) {
			Map.Entry entry = (Map.Entry) it.next();
			String k = (String) entry.getKey();
			Object v = entry.getValue();
			if (null != v && !"".equals(v) && !"sign".equals(k)
					&& !"key".equals(k)) {
				sb.append(k + "=" + v + "&");
			}
		}
		sb.append("key=" + partnerkey);
		System.out.println("sb=============="+sb.toString());
		String sign = MD5Encode(sb.toString(), characterEncoding).toUpperCase();
		return sign;
	}

	private static String byteArrayToHexString(byte b[]) {
		StringBuffer resultSb = new StringBuffer();
		for (int i = 0; i < b.length; i++)
			resultSb.append(byteToHexString(b[i]));

		return resultSb.toString();
	}

	/**
	 * md5加密
	 */
	private static final String hexDigits[] = { "0", "1", "2", "3", "4", "5",
			"6", "7", "8", "9", "a", "b", "c", "d", "e", "f" };

	private static String byteToHexString(byte b) {
		int n = b;
		if (n < 0)
			n += 256;
		int d1 = n / 16;
		int d2 = n % 16;
		return hexDigits[d1] + hexDigits[d2];
	}

	public static String MD5Encode(String origin, String charsetname) {
		String resultString = null;
		try {
			resultString = new String(origin);
			MessageDigest md = MessageDigest.getInstance("MD5");
			if (charsetname == null || "".equals(charsetname))
				resultString = byteArrayToHexString(md.digest(resultString
						.getBytes()));
			else
				resultString = byteArrayToHexString(md.digest(resultString
						.getBytes(charsetname)));
		} catch (Exception exception) {
		}
		return resultString;
	}

	/**
	 * @Description：将请求参数转换为xml格式的string
	 * @param parameters
	 *            请求参数
	 * @return
	 */
	public static String getRequestXml(SortedMap<Object, Object> parameters) {
		StringBuffer sb = new StringBuffer();
		sb.append("<xml>");
		Set es = parameters.entrySet();
		Iterator it = es.iterator();
		while (it.hasNext()) {
			Map.Entry entry = (Map.Entry) it.next();
			String k = (String) entry.getKey();
			String v = (String) entry.getValue().toString();
			if ("attach".equalsIgnoreCase(k) || "body".equalsIgnoreCase(k)) {
				sb.append("<" + k + ">" + "<![CDATA[" + v + "]]></" + k + ">");
			} else {
				sb.append("<" + k + ">" + v + "</" + k + ">");
			}
		}
		sb.append("</xml>");
		return sb.toString();
	}

	
	/**
	 * 支付宝支付
	 */
	//商户号
	public static String alipartner = "";  
	//商户的私钥
	public static String private_key = "";  
	//支付宝公钥
	public static String alipay_public_key ="";
	//APPID  
    public static String app_id="";  
    //notify_url  
    public static String notify_url="http://192.168.188.122:8080/huaji/ws/user/alipaynotify";  
	@Override
	public Map<String, Object> alipay(String subject,String out_trade_no,String total_amount) {
		Map<String, Object> paymap = new HashMap<String, Object>();
		// 实例化客户端 charset
		AlipayClient alipayClient = new DefaultAlipayClient("https://alipay.trade.app.pay", app_id,
				private_key, "json", "UTF-8", alipay_public_key, "RSA2");
		// 实例化具体API对应的request类,类名称和接口名称对应,当前调用接口名称：alipay.trade.app.pay
		AlipayTradeAppPayRequest request = new AlipayTradeAppPayRequest();
		// SDK已经封装掉了公共参数，这里只需要传入业务参数。以下方法为sdk的model入参方式(model和biz_content同时存在的情况下取biz_content)。
		AlipayTradeAppPayModel model = new AlipayTradeAppPayModel();
		model.setBody("我是测试数据");
		try {
			
			String s = new String(subject.getBytes("ISO-8859-1"), "UTF-8");
			model.setSubject(s);
			//System.out.println("s==="+s);
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		model.setOutTradeNo(out_trade_no);
		model.setTimeoutExpress("30m");
		model.setTotalAmount(total_amount);
		model.setProductCode("QUICK_MSECURITY_PAY");
		request.setBizModel(model);
		request.setNotifyUrl(notify_url);
		try {
			// 这里和普通的接口调用不同，使用的是sdkExecute
			AlipayTradeAppPayResponse response = alipayClient.sdkExecute(request);
			System.out.println(response.getBody());// 就是orderString
													// 可以直接给客户端请求，无需再做处理。
			paymap.put("result", response.getBody());
		} catch (AlipayApiException e) {
			e.printStackTrace();
		}
		return paymap;
	}
	
	
	public void alipaynotify(HttpServletRequest request){
		 System.out.println("支付宝支付结果通知");
		//获取支付宝POST过来反馈信息
		 Map<String,String> params = new HashMap<String,String>();
		 Map requestParams = request.getParameterMap();
		 for (Iterator iter = requestParams.keySet().iterator(); iter.hasNext();) {
		     String name = (String) iter.next();
		     String[] values = (String[]) requestParams.get(name);
		     String valueStr = "";
		     for (int i = 0; i < values.length; i++) {
		         valueStr = (i == values.length - 1) ? valueStr + values[i]
		                     : valueStr + values[i] + ",";
		   	}
		     //乱码解决，这段代码在出现乱码时使用。
		 	//valueStr = new String(valueStr.getBytes("ISO-8859-1"), "utf-8");
		 	params.put(name, valueStr);
		 }
		 //切记alipaypublickey是支付宝的公钥，请去open.alipay.com对应应用下查看。
		 //boolean AlipaySignature.rsaCheckV1(Map<String, String> params, String publicKey, String charset, String sign_type)
		 try {
			boolean flag = AlipaySignature.rsaCheckV1(params, alipay_public_key, "UTF-8","RSA2");
		} catch (AlipayApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	@Override
	public Map<String, Object> update(String userName, String pwd) {
		// TODO Auto-generated method stub
		return null;
	}

}
